; crc_iso14443_nasm.asm
; CRC-16 for ISO/IEC 14443-3 Type A (NASM, x86-64, System V ABI).
; Polynomial 0x1021, init 0x6363.
; Signature: uint16_t crc16_iso14443a(const uint8_t *data, size_t len);
; rdi = data, rsi = len, return in ax.

section .text
global crc16_iso14443a

crc16_iso14443a:
    mov     eax, 0x00006363
    xor     rcx, rcx

.outer:
    cmp     rcx, rsi
    jae     .done

    movzx   edx, byte [rdi + rcx]
    shl     edx, 8
    xor     eax, edx

    mov     r8d, 8
.inner:
    test    eax, 0x00008000
    jz      .no_xor
    shl     eax, 1
    xor     eax, 0x00001021
    jmp     .next
.no_xor:
    shl     eax, 1
.next:
    dec     r8d
    jnz     .inner

    inc     rcx
    jmp     .outer

.done:
    and     eax, 0x0000FFFF
    ret
