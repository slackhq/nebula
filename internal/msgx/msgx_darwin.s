//go:build !ios

#include "textflag.h"

// The same trampoline shape x/sys/unix uses for its libSystem stubs; it assembles for amd64 and arm64 alike.
TEXT msgx_dlsym_trampoline<>(SB),NOSPLIT,$0-0
	JMP	msgx_dlsym(SB)
GLOBL	·dlsymTrampolineAddr(SB), RODATA, $8
DATA	·dlsymTrampolineAddr(SB)/8, $msgx_dlsym_trampoline<>(SB)
