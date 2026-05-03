; Assembly module for low-level CPU/hardware access
; x86_64 Linux NASM syntax

section .text
global asm_cpuid
global asm_get_cpu_vendor
global asm_get_cpu_brand
global asm_get_cpu_signature
global asm_read_msr
global asm_has_rdtscp
global asm_read_tsc

; void asm_cpuid(uint32_t leaf, uint32_t subleaf, cpuid_result_t *result)
; leaf = rdi, subleaf = rsi, result = rdx
asm_cpuid:
    push rbx
    push r12
    mov r12, rdx        ; Save result pointer
    
    mov eax, edi        ; leaf
    mov ecx, esi        ; subleaf
    cpuid
    
    mov [r12 + 0], eax  ; result->eax
    mov [r12 + 4], ebx  ; result->ebx
    mov [r12 + 8], ecx  ; result->ecx
    mov [r12 + 12], edx ; result->edx
    
    pop r12
    pop rbx
    ret

; void asm_get_cpu_vendor(char *buffer)
; rdi = buffer (12 chars minimum)
asm_get_cpu_vendor:
    push rbx
    
    xor eax, eax        ; CPUID leaf 0 - vendor string
    cpuid
    
    mov [rdi + 0], ebx
    mov [rdi + 4], edx
    mov [rdi + 8], ecx
    mov byte [rdi + 12], 0
    
    pop rbx
    ret

; void asm_get_cpu_brand(char *buffer)
; rdi = buffer (48 chars minimum)
asm_get_cpu_brand:
    push rbx
    push r12
    mov r12, rdi        ; Save buffer pointer
    
    ; Check if extended CPUID is supported
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000004
    jb .no_brand
    
    ; Get brand string (3 leaves: 0x80000002, 0x80000003, 0x80000004)
    mov eax, 0x80000002
    cpuid
    mov [r12 + 0], eax
    mov [r12 + 4], ebx
    mov [r12 + 8], ecx
    mov [r12 + 12], edx
    
    mov eax, 0x80000003
    cpuid
    mov [r12 + 16], eax
    mov [r12 + 20], ebx
    mov [r12 + 24], ecx
    mov [r12 + 28], edx
    
    mov eax, 0x80000004
    cpuid
    mov [r12 + 32], eax
    mov [r12 + 36], ebx
    mov [r12 + 40], ecx
    mov [r12 + 44], edx
    mov byte [r12 + 48], 0
    
    ; Trim leading spaces
    mov rcx, 48
.trim_loop:
    mov al, [r12]
    cmp al, ' '
    jne .done
    ; Shift string left by 1
    push r12
    push rcx
    mov rsi, r12
    mov rdi, r12
    inc rsi
    mov rcx, 47
    rep movsb
    pop rcx
    pop r12
    loop .trim_loop
    
.done:
    pop r12
    pop rbx
    ret
    
.no_brand:
    mov byte [r12], 0
    pop r12
    pop rbx
    ret

; uint32_t asm_get_cpu_signature(void)
asm_get_cpu_signature:
    push rbx
    mov eax, 1          ; CPUID leaf 1
    cpuid
    ; Return signature in EAX
    pop rbx
    ret

; uint64_t asm_read_msr(uint32_t msr)
; rdi = msr number
asm_read_msr:
    push rbx
    mov ecx, edi        ; MSR number
    rdmsr               ; Read MSR into EDX:EAX
    shl rdx, 32         ; Combine into RAX
    or rax, rdx
    pop rbx
    ret

; int asm_has_rdtscp(void)
asm_has_rdtscp:
    push rbx
    mov eax, 0x80000001 ; Extended CPUID
    cpuid
    mov eax, edx
    shr eax, 27         ; RDTSCP flag is bit 27
    and eax, 1
    pop rbx
    ret

; uint64_t asm_read_tsc(void)
asm_read_tsc:
    push rbx
    rdtsc               ; Read TSC into EDX:EAX
    shl rdx, 32
    or rax, rdx
    pop rbx
    ret

; Additional low-level hardware access functions

; int asm_cpu_has_feature(uint32_t feature)
; feature bits: 0-31 = EDX from CPUID(1), 32-63 = ECX from CPUID(1)
; rdi = feature number
asm_cpu_has_feature:
    push rbx
    mov r12d, edi       ; Save feature number
    
    mov eax, 1
    cpuid
    
    cmp r12d, 32
    jb .check_edx
    
    ; Check ECX
    sub r12d, 32
    mov eax, ecx
    jmp .do_check
    
.check_edx:
    mov eax, edx
    
.do_check:
    mov cl, r12b
    shr eax, cl
    and eax, 1
    
    pop rbx
    ret
