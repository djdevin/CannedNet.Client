#include "common.h"

#include "detour.h"
#include "logger.h"


//
// 14-byte absolute indirect jump: FF 25 00000000 <8-byte target>. rip-relative disp=0 means the
// 64-bit pointer sits immediately after the 6-byte opcode, so this needs no register and can reach
// anywhere in the address space.
//
#define JMP_PATCH_LEN 14

// Trampoline capacity: stolen bytes (<= ~24) + the 14-byte jump back.
#define TRAMP_SIZE 128


//
// How a copied instruction must be fixed up once relocated to the trampoline.
//
typedef enum
{
    RK_NONE,          // position-independent, copy verbatim
    RK_RIPREL,        // has a rip-relative disp32 operand (mod=00,rm=101)
    RK_REL32,         // CALL/JMP rel32 (E8/E9)
    RK_UNSUPPORTED    // rel8 branch etc. -- we won't relocate it, refuse the hook
} reloc_kind;

typedef struct
{
    size_t      len;       // total instruction length
    reloc_kind  kind;
    size_t      disp_off;  // offset of the disp32/rel32 field within the instruction
} insn_t;


//
// Minimal x86-64 length decoder + relocation classifier.
//
// Measures whole-instruction boundaries so a trampoline never copies a torn instruction, and flags
// the two relocation cases we can fix (rip-relative disp32, rel32 branch). Returns 1 on success with
// *out filled; 0 if it hits an opcode we don't model (caller then refuses the hook rather than
// corrupt code). rel8 branches are modelled (so length is known) but flagged RK_UNSUPPORTED.
//
static int decode(const uint8_t *p, insn_t *out)
{
    size_t n = 0;
    int opsize = 0;      // 0x66 present
    int rexW = 0;
    out->kind = RK_NONE;
    out->disp_off = 0;

    // Legacy prefixes.
    for (;;)
    {
        uint8_t c = p[n];
        if (c == 0x66) { opsize = 1; n++; continue; }
        if (c == 0x67 || c == 0xF0 || c == 0xF2 || c == 0xF3 ||
            c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26 ||
            c == 0x64 || c == 0x65) { n++; continue; }
        break;
    }

    // REX prefix (0x40-0x4F).
    if ((p[n] & 0xF0) == 0x40) { rexW = (p[n] & 0x08) != 0; n++; }

    uint8_t op = p[n++];

    if (op == 0x0F)
        return 0;        // two-byte opcodes: unsupported here, bail

    // Relative branches. rel32 forms we can relocate; rel8 we model (length) but won't move.
    if (op == 0xE8 || op == 0xE9)                       // CALL/JMP rel32
    {
        out->kind = RK_REL32;
        out->disp_off = n;
        n += 4;
        out->len = n;
        return 1;
    }
    if ((op >= 0x70 && op <= 0x7F) ||                   // Jcc rel8
        (op >= 0xE0 && op <= 0xE3) ||                   // LOOP/JrCXZ
        op == 0xEB)                                     // JMP rel8
    {
        out->kind = RK_UNSUPPORTED;
        n += 1;
        out->len = n;
        return 1;
    }

    // Does this opcode carry a ModR/M byte?
    int hasModRM =
        ( op <= 0x3F && (op & 0x07) < 0x04 ) ||               // arith r/m forms
        op == 0x62 || op == 0x63 || op == 0x69 || op == 0x6B ||
        ( op >= 0x80 && op <= 0x8F ) ||                        // grp1/test/xchg/mov/lea/pop
        op == 0xC0 || op == 0xC1 || op == 0xC6 || op == 0xC7 ||
        ( op >= 0xD0 && op <= 0xD3 ) ||
        ( op >= 0xD8 && op <= 0xDF ) ||                        // x87
        op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF;

    uint8_t modrm_reg = 0;

    if (hasModRM)
    {
        uint8_t modrm = p[n++];
        uint8_t mod = modrm >> 6;
        uint8_t rm  = modrm & 0x07;
        modrm_reg   = (modrm >> 3) & 0x07;

        if (mod != 0x03)
        {
            if (rm == 0x04)                       // SIB
            {
                uint8_t sib = p[n++];
                uint8_t base = sib & 0x07;
                if (mod == 0x00 && base == 0x05) n += 4;   // disp32, no base
                else if (mod == 0x01)            n += 1;
                else if (mod == 0x02)            n += 4;
            }
            else
            {
                if (mod == 0x00)
                {
                    if (rm == 0x05)               // rip-relative disp32
                    {
                        out->kind = RK_RIPREL;
                        out->disp_off = n;
                        n += 4;
                    }
                }
                else if (mod == 0x01) n += 1;
                else if (mod == 0x02) n += 4;
            }
        }
    }

    // Immediate size (comes AFTER any disp -- matters for rip-relative rip = end of whole insn).
    size_t imm = 0;
    switch (op)
    {
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
        case 0x6A: case 0x6B: case 0x80: case 0x82: case 0x83:
        case 0xA8: case 0xC0: case 0xC1: case 0xC6:
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            imm = 1; break;

        case 0xC2: case 0xCA:                     // ret imm16
            imm = 2; break;

        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
        case 0x68: case 0x69: case 0x81: case 0xA9:
        case 0xC7:
            imm = opsize ? 2 : 4; break;

        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:  // mov r,imm (imm64 if REX.W)
            imm = rexW ? 8 : (opsize ? 2 : 4); break;

        case 0xF6:                                // grp3: imm8 only for TEST (reg 0/1)
            if (modrm_reg <= 1) imm = 1; break;
        case 0xF7:                                // grp3: imm16/32 for TEST (reg 0/1)
            if (modrm_reg <= 1) imm = opsize ? 2 : 4; break;

        default: break;
    }
    n += imm;

    out->len = n;
    return 1;
}


//
// Sum whole instructions until we have at least JMP_PATCH_LEN bytes to overwrite. 0 => a decode
// failed (unknown opcode) and the hook must be refused.
//
static size_t steal_len(const uint8_t *target)
{
    size_t total = 0;
    insn_t insn;
    while (total < JMP_PATCH_LEN)
    {
        if (!decode(target + total, &insn)) return 0;
        total += insn.len;
    }
    return total;
}


static void WriteAbsJump(BYTE *at, LPVOID dest)
{
    at[0] = 0xFF; at[1] = 0x25;
    at[2] = at[3] = at[4] = at[5] = 0x00;
    *(void **)&at[6] = dest;
}


//
// Allocate executable memory within +-2GB of target, so relocated rip-relative disp32 / rel32
// fields (which reference addresses near the original code) still encode in 32 bits. Falls back to
// anywhere; the per-field range check in InstallDetour is the safety net if that isn't close enough.
//
static LPVOID AllocNear(void *target, size_t size)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t gran = si.dwAllocationGranularity;

    uintptr_t t = (uintptr_t)target;
    uintptr_t base = t & ~(gran - 1);

    const uintptr_t MAXDIST = 0x70000000ULL;   // ~1.87GB, margin under the 2GB limit

    for (uintptr_t off = gran; off < MAXDIST; off += gran)
    {
        uintptr_t lo = base - off;
        if (lo < base)   // no underflow
        {
            LPVOID p = VirtualAlloc((LPVOID)lo, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }

        uintptr_t hi = base + off;
        if (hi > base)   // no overflow
        {
            LPVOID p = VirtualAlloc((LPVOID)hi, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
    }

    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}


//
// Copy [target, target+stolen) into the trampoline, fixing rip-relative and rel32 operands for the
// new location. Returns 1 on success, 0 if an instruction can't be relocated (rel8, or a fixup that
// no longer fits in int32).
//
static int RelocateInto(BYTE *tramp, const uint8_t *target, size_t stolen)
{
    size_t off = 0;
    insn_t insn;

    while (off < stolen)
    {
        if (!decode(target + off, &insn))
            return 0;

        memcpy(tramp + off, target + off, insn.len);

        if (insn.kind == RK_RIPREL || insn.kind == RK_REL32)
        {
            const uint8_t *src = target + off;
            BYTE *dst = tramp + off;

            // rip is relative to the END of the whole instruction (past any trailing immediate),
            // so use insn.len, not disp_off+4.
            int32_t oldDisp = *(int32_t *)(src + insn.disp_off);
            uintptr_t absTarget = (uintptr_t)src + insn.len + (intptr_t)oldDisp;

            int64_t newDisp = (int64_t)absTarget - (int64_t)((uintptr_t)dst + insn.len);
            if (newDisp > INT32_MAX || newDisp < INT32_MIN)
            {
                Log("[DETOUR] relocation out of int32 range at +%zu -- refusing", off);
                return 0;
            }

            *(int32_t *)(dst + insn.disp_off) = (int32_t)newDisp;
        }
        else if (insn.kind == RK_UNSUPPORTED)
        {
            Log("[DETOUR] rel8 branch in stolen prologue at +%zu -- refusing (needs rel8->rel32 rewrite)", off);
            return 0;
        }

        off += insn.len;
    }

    return 1;
}


int InstallDetour(
    LPVOID target,
    LPVOID hook,
    BYTE *backup,
    LPVOID *outTrampoline
)
{
    if (!target || !hook)
    {
        Log("[DETOUR] Invalid target/hook");
        return 0;
    }


    //
    // How many bytes we overwrite at the entry. For a call-through hook (outTrampoline != NULL) we
    // steal whole instructions, relocate them into a trampoline, and chain back to the original.
    // For a replace-only hook (outTrampoline == NULL, e.g. the SSL accept-all that never calls the
    // original) 14 bytes is enough -- we jump away immediately, so a torn trailing instruction is
    // never executed.
    //
    size_t stolen = JMP_PATCH_LEN;

    if (outTrampoline)
    {
        stolen = steal_len((const uint8_t *)target);
        if (stolen == 0)
        {
            Log("[DETOUR] %p: undecodable prologue -- refusing hook", target);
            return 0;
        }
    }


    // Preserve the original bytes for the caller.
    memcpy(backup, target, stolen);


    //
    // Build the trampoline (call-through hooks only): relocated stolen instructions + jump back.
    //
    LPVOID trampoline = NULL;

    if (outTrampoline)
    {
        trampoline = AllocNear(target, TRAMP_SIZE);
        if (!trampoline)
        {
            Log("[DETOUR] trampoline allocation failed");
            return 0;
        }

        if (!RelocateInto((BYTE *)trampoline, (const uint8_t *)target, stolen))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return 0;
        }

        WriteAbsJump((BYTE *)trampoline + stolen, (BYTE *)target + stolen); // resume original
        FlushInstructionCache(GetCurrentProcess(), trampoline, stolen + JMP_PATCH_LEN);
    }


    //
    // Overwrite the entry: 14-byte jump to hook, NOP-pad any remaining stolen bytes so no torn
    // instruction is left in the live code stream.
    //
    DWORD oldProtect;
    if (!VirtualProtect(target, stolen, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        Log("[DETOUR] VirtualProtect failed %lu", GetLastError());
        if (trampoline) VirtualFree(trampoline, 0, MEM_RELEASE);
        return 0;
    }

    WriteAbsJump((BYTE *)target, hook);
    for (size_t i = JMP_PATCH_LEN; i < stolen; i++)
        ((BYTE *)target)[i] = 0x90;                                // NOP pad

    DWORD tmp;
    VirtualProtect(target, stolen, oldProtect, &tmp);
    FlushInstructionCache(GetCurrentProcess(), target, stolen);


    if (outTrampoline)
        *outTrampoline = trampoline;


    Log("[DETOUR] %p -> %p (stole %zu bytes%s)", target, hook, stolen,
        outTrampoline ? ", relocated trampoline" : "");
    return 1;
}
