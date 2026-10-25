; crc_iso14443.asm
; CRC-16 for ISO/IEC 14443-3 Type A.
; Polynomial 0x1021, init 0x6363, MSB-first, no final XOR.
;
; Assemble with ML64 (MSVC/Windows x64):
;   ml64 /c /Fo crc_iso14443.obj asm\crc_iso14443.asm
;
; Link into the Rust crate by adding to build.rs:
;   println!("cargo:rustc-link-arg=crc_iso14443.obj");
;
; Signature (Windows x64 ABI):
;   uint16_t crc16_iso14443a(const uint8_t *data, size_t len);
;   rcx = data, rdx = len, return value in ax.

.code

crc16_iso14443a PROC
    mov     eax, 6363h              ; crc = 0x6363
    xor     r8, r8                  ; i = 0

outer_loop:
    cmp     r8, rdx
    jae     done

    movzx   r9d, byte ptr [rcx + r8] ; byte = data[i]
    shl     r9d, 8
    xor     eax, r9d                ; crc ^= byte << 8

    mov     r10d, 8                 ; j = 8
inner_loop:
    test    eax, 8000h
    jz      no_xor
    shl     eax, 1
    xor     eax, 1021h
    jmp     next_bit
no_xor:
    shl     eax, 1
next_bit:
    dec     r10d
    jnz     inner_loop

    inc     r8
    jmp     outer_loop

done:
    and     eax, 0FFFFh
    ret
crc16_iso14443a ENDP

END
