#pragma once

// Neutralises the file-signature-check P/Invoke that calls through an unresolved native pointer and
// eventually kills the process. See src/unity/filesig_patch.c.
void PatchFileSigCheck(void);
