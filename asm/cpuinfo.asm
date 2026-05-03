; модуль ассемблера для низкоуровневого доступа к процессору/железу
; синтаксис nasm x86_64 linux

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
    mov r12, rdx        ; сохраняем указатель на результат
    
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
; rdi = буфер (минимум 12 символов)
asm_get_cpu_vendor:
    push rbx
    
    xor eax, eax        ; cpuid leaf 0 - строка производителя
    cpuid
    
    mov [rdi + 0], ebx
    mov [rdi + 4], edx
    mov [rdi + 8], ecx
    mov byte [rdi + 12], 0
    
    pop rbx
    ret

; void asm_get_cpu_brand(char *buffer)
; rdi = буфер (минимум 48 символов)
asm_get_cpu_brand:
    push rbx
    push r12
    mov r12, rdi        ; сохраняем указатель на буфер
    
    ; проверка поддержки расширенного cpuid
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000004
    jb .no_brand
    
    ; получение строки бренда (3 листа: 0x80000002, 0x80000003, 0x80000004)
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
    
    ; обрезка начальных пробелов
    mov rcx, 48
.trim_loop:
    mov al, [r12]
    cmp al, ' '
    jne .done
    ; сдвиг строки влево на 1
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
    mov eax, 1          ; cpuid leaf 1
    cpuid
    ; возврат сигнатуры в eax
    pop rbx
    ret

; uint64_t asm_read_msr(uint32_t msr)
; rdi = номер msr
asm_read_msr:
    push rbx
    mov ecx, edi        ; номер msr
    rdmsr               ; чтение msr в edx:eax
    shl rdx, 32         ; объединение в rax
    or rax, rdx
    pop rbx
    ret

; int asm_has_rdtscp(void)
asm_has_rdtscp:
    push rbx
    mov eax, 0x80000001 ; расширенный cpuid
    cpuid
    mov eax, edx
    shr eax, 27         ; флаг rdtscp - бит 27
    and eax, 1
    pop rbx
    ret

; uint64_t asm_read_tsc(void)
asm_read_tsc:
    push rbx
    rdtsc               ; чтение tsc в edx:eax
    shl rdx, 32
    or rax, rdx
    pop rbx
    ret

; дополнительные функции низкоуровневого доступа к железу

; int asm_cpu_has_feature(uint32_t feature)
; feature bits: 0-31 = EDX from CPUID(1), 32-63 = ECX from CPUID(1)
; rdi = номер фичи
asm_cpu_has_feature:
    push rbx
    mov r12d, edi       ; сохраняем номер фичи
    
    mov eax, 1
    cpuid
    
    cmp r12d, 32
    jb .check_edx
    
    ; проверка ecx
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
