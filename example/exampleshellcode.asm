use32

    ;reloc should Point To .data + 0x0000
    call getBaseAddress
    mov ebx,eax
    add eax,4
    add ebx,40
    mov [eax],ebx
    
    ;reloc should Point To .data + 0x0000
    call getBaseAddress
    mov ebx,eax
    add eax,15
    add ebx,40
    mov [eax],ebx
    
    ;reloc should Point To .rdata + 0x0000
    call getBaseAddress
    mov ebx,eax
    add eax,40
    add ebx,24
    mov [eax],ebx
    
        call getBaseAddress
        add eax,0
        push eax
        ret ; this is a jump to entry symbol
        getBaseAddress: ;uses eip to find start of shellcode
            call next___
            next___:
            pop eax
            add eax,5
            ret
        BaseAddress:
        db 85,137,229,161,0,0,0,0,131,192,4,198,0,120,161,0,0,0,0,93,195,144,144,144,104,101,108,108,111,32,119,111,114,108,100,33,0,0,0,0,0,0,0,0
        