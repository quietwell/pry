; BpTrapAsm.asm — v11 int1 (#DB) interception stub (ml64).
;
; Installed over every CPU's IDT[1] by PryBpTrapInstall (BpTrap.c).
; On entry the CPU pushed [RIP][CS][RFLAGS] plus [RSP][SS] when the hit
; came from CPL3 (non-KVAS hosts route user-mode #DBs through the kernel
; IDT too — the stub handles both frame shapes; CS.RPL decides swapgs).
;
; The stub snapshots the volatile regs, calls PryBpTrapDispatch, and:
;   * consumed (eax!=0): the C side already set RF in the frame's RFLAGS
;     (exec BPs re-fault on resume otherwise), restore regs and iretq.
;   * foreign (eax==0): restore regs and jmp the saved KiTrap01 — the
;     machine behaves exactly as if the hook weren't there.
;
; PryBpTrapInStub counts in-flight stubs so PryBpTrapUninstall can
; wait for the last dispatch to leave the image before restoring IDTs.

EXTERN PryBpTrapDispatch    : PROC
EXTERN PryBpTrapChainTarget : QWORD
EXTERN PryBpTrapInStub      : DWORD

.code

PryBpTrapStub PROC
    ; swap to kernel GS when the trap came from user mode
    test    byte ptr [rsp+8], 3         ; CS.RPL in the trap frame
    jz      short @@kentry
    swapgs
@@kentry:
    ; save volatiles (+ rbx as our nonvolatile scratch). After 8 pushes
    ; the CPU's trap frame sits at rsp+64: +0 RIP, +8 CS, +16 RFLAGS,
    ; (+24 RSP, +32 SS when the entry was from CPL3).
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    r8
    push    r9
    push    r10
    push    r11
    mov     rbx, rsp                    ; rbx -> push block; frame at rbx+64

    lock inc dword ptr [PryBpTrapInStub]

    and     rsp, -16                    ; ABI alignment for the call
    ; 144 (90h) bytes, 16-aligned: XMM0-5 (96) + MXCSR slot (16, padded) +
    ; callee shadow space (32). The C dispatch uses SSE (memcpy/memset-
    ; style codegen, floating comparisons, ...) and would otherwise
    ; silently clobber the interrupted thread's XMM0-5/MXCSR -- there is
    ; no hardware save/restore for them across an interrupt, unlike the
    ; GP regs this stub already pushes by hand.
    sub     rsp, 90h
    movaps  [rsp+00h], xmm0
    movaps  [rsp+10h], xmm1
    movaps  [rsp+20h], xmm2
    movaps  [rsp+30h], xmm3
    movaps  [rsp+40h], xmm4
    movaps  [rsp+50h], xmm5
    stmxcsr [rsp+60h]
    mov     rcx, [rbx+64]               ; arg1: faulting RIP
    mov     rdx, [rbx+72]               ; arg2: CS (kernel vs user entry)
    lea     r8,  [rbx+80]               ; arg3: &RFLAGS (C sets RF here)
    cld                                 ; ABI requires DF=0 on any call; the
                                         ; interrupted thread's real DF comes
                                         ; back for free -- iretq pops RFLAGS
                                         ; from the (untouched) trap frame on
                                         ; the consumed path, and the chain
                                         ; target (KiTrap01) expects a clear
                                         ; DF on entry the same way this one
                                         ; does
    call    PryBpTrapDispatch
    ldmxcsr [rsp+60h]
    movaps  xmm5, [rsp+50h]
    movaps  xmm4, [rsp+40h]
    movaps  xmm3, [rsp+30h]
    movaps  xmm2, [rsp+20h]
    movaps  xmm1, [rsp+10h]
    movaps  xmm0, [rsp+00h]
    mov     rsp, rbx                    ; unwind the aligned call frame
    lock dec dword ptr [PryBpTrapInStub]
    test    eax, eax
    jz      short @@chain

    ; consumed: record already queued, RF already set — resume.
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    test    byte ptr [rsp+8], 3         ; hand GS back on a user entry
    jz      short @@iret
    swapgs
@@iret:
    iretq

@@chain:
    ; not ours (single-step, foreign DRs, no subscription) — restore the
    ; pre-entry state and transfer to the saved handler.
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    test    byte ptr [rsp+8], 3
    jz      short @@jmp
    swapgs
@@jmp:
    jmp     qword ptr [PryBpTrapChainTarget]
PryBpTrapStub ENDP

END
