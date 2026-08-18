; Return-address spoofing thunk for il2cpp utility calls (defeats stack-walk-based anti-cheat
; detection -- see include/retspoof.h for the rationale).
;
; uint64_t spoof_call(void* gadget, void* target, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
;   rcx=gadget   address of a "jmp qword ptr [rbx]" (bytes FF 23) instruction inside the game module
;   rdx=target   function to call
;   r8=a1  r9=a2  [rsp+28h]=a3  [rsp+30h]=a4      (standard Windows x64 arg registers/stack)
;
; Calls target(a1,a2,a3,a4) with a spoofed return address: instead of target's `ret` landing back in
; this thunk (inside redirector.dll), it lands on `gadget` -- a real instruction inside the game's own
; module -- which does `jmp [rbx]` back to us. rbx is a callee-saved (non-volatile) register, so target
; is required by the calling convention to preserve it across its own execution; we use that guarantee
; to smuggle our real resume address across the call via a stack slot rbx points at. Any stack walk
; that reads target's return address off the stack (RtlCaptureStackBackTrace, manual unwind, etc.) sees
; `gadget` -- an address inside the legitimate module -- instead of redirector.dll.

.code

spoof_call PROC
    mov r10, [rsp+28h]         ; a3 (5th arg, passed on the stack)
    mov r11, [rsp+30h]         ; a4 (6th arg, passed on the stack)

    push rbx                    ; non-volatile; target must preserve it across its own call (ABI)
    sub  rsp, 40h                ; local frame (64B, 16-aligned): gadget/target/a1..a4/resumeAddr/pad

    mov  [rsp+00h], rcx          ; gadget
    mov  [rsp+08h], rdx          ; target
    mov  [rsp+10h], r8           ; a1
    mov  [rsp+18h], r9           ; a2
    mov  [rsp+20h], r10          ; a3
    mov  [rsp+28h], r11          ; a4

    lea  rax, resume_lbl
    mov  [rsp+30h], rax          ; stash the address to resume at once target returns

    lea  rbx, [rsp+30h]          ; rbx -> pointer to the resume-address slot; the gadget dereferences
                                   ; this via `jmp [rbx]` once target's `ret` "returns" to it.

    mov  rcx, [rsp+10h]
    mov  rdx, [rsp+18h]
    mov  r8,  [rsp+20h]
    mov  r9,  [rsp+28h]
    mov  r10, [rsp+00h]          ; gadget
    mov  r11, [rsp+08h]          ; target

    sub  rsp, 20h                 ; shadow space for target's own arg spill (real, unused scratch)
    push r10                       ; fake return address (the gadget) -- mimics what `call` would push
    jmp  r11                        ; enter target with a spoofed return address already on the stack

resume_lbl:
    ; Reached via: target's `ret` pops `gadget` and "returns" to it; the gadget's `jmp [rbx]` reads the
    ; resume-address slot rbx still points at (target preserved rbx per the ABI) and jumps here. rax
    ; holds target's return value, untouched by the detour through the gadget.
    add  rsp, 20h                 ; undo the shadow-space reservation
    add  rsp, 40h                 ; undo the local frame
    pop  rbx                       ; restore caller's rbx
    ret

spoof_call ENDP

END
