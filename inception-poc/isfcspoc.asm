; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
    include \masm32\include\masm32rt.inc
; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

    .data?
      lpFlOldAddress    dw  ?

    .data
      message db "5! = %d", 10, 0
    .code


start:
    call main
    exit

main proc

    pushad

    mov     eax, offset ProtectedCodeBoundarySta    ; Start of Code Boundary
    mov     ecx, offset ProtectedCodeBoundaryEnd    ; End of Code Boundary
    sub     ecx, eax                                ; Compute Code Segment Size

    pushad
    invoke  VirtualProtect, eax, ecx, PAGE_READWRITE, offset lpFlOldAddress
    popad

    db      0EBh
    db      04h
    dd      0h

    mov     edx, eax
    mov     ebx, eax
    add     ebx, ecx
    REP_BYTE_ENC_LOOP:
    xor     byte ptr [edx], 0AAh
    inc     edx
    cmp     edx, ebx
    jne     REP_BYTE_ENC_LOOP

    db      0EBh
    db      04h
    dd      0h

    mov     edx, eax
    mov     ebx, eax
    add     ebx, ecx
    REP_BYTE_DEC_LOOP:
    xor     byte ptr [edx], 0AAh
    inc     edx
    cmp     edx, ebx
    jne     REP_BYTE_DEC_LOOP

    popad

    pushad
    invoke  VirtualProtect, eax, ecx, offset lpFlOldAddress, offset lpFlOldAddress
    popad

    jmp     ProtectedCodeBoundarySta
    db      00
    db      00
    db      00
    db      00
    
ProtectedCodeBoundarySta:

    mov     eax, 01h
    mov     ecx, 05h
    
ComputeLoop:
    imul    eax, ecx
    dec     ecx
    cmp     ecx, 0h
    jne     ComputeLoop

    invoke  crt_printf, offset message, eax
    
ProtectedCodeBoundaryEnd:
    
    ret
main endp

end start
