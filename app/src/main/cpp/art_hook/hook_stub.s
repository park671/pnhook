    .text
    .global hookStub
hookStub:
        sub sp, sp, #256
        b #-4
        str x0, [sp, #0]
        str x1, [sp, #8]
        str x2, [sp, #16]
        str x3, [sp, #24]
        str x4, [sp, #32]
        str x5, [sp, #40]
        str x6, [sp, #48]
        str x7, [sp, #56]
        str x30, [sp, #240]

        bl parkHookBefore
        bl getBackupMethodPtr
        mov x16, x0

        ldr x7, [sp, #56]
        ldr x6, [sp, #48]
        ldr x5, [sp, #40]
        ldr x4, [sp, #32]
        ldr x3, [sp, #24]
        ldr x2, [sp, #16]
        ldr x1, [sp, #8]
        ldr x0, [sp, #0]

        blr x16

        str x0, [sp, #0]

        bl parkHookAfter

        ldr x0, [sp, #0]
        ldr x30, [sp, #240]
        add sp, sp, #256
        ret