; дополнительные процедуры доступа к железу на ассемблере
; синтаксис nasm x86_64 linux

section .text
global asm_read_cr0
global asm_read_cr2
global asm_read_cr3
global asm_read_cr4
global asm_get_flags
global asm_check_sse2
global asm_check_avx
global asm_get_tsc_freq

; uint64_t asm_read_cr0(void)
asm_read_cr0:
    mov rax, cr0
    ret

; uint64_t asm_read_cr2(void)
asm_read_cr2:
    mov rax, cr2
    ret

; uint64_t asm_read_cr3(void)
asm_read_cr3:
    mov rax, cr3
    ret

; uint64_t asm_read_cr4(void)
asm_read_cr4:
    mov rax, cr4
    ret

; uint64_t asm_get_flags(void)
asm_get_flags:
    pushfq
    pop rax
    ret

; int asm_check_sse2(void)
asm_check_sse2:
    push rbx
    mov eax, 1
    cpuid
    test edx, (1 << 26)    ; бит sse2
    setnz al
    movzx eax, al
    pop rbx
    ret

; int asm_check_avx(void)
asm_check_avx:
    push rbx
    mov eax, 1
    cpuid
    test ecx, (1 << 28)    ; бит avx
    setnz al
    movzx eax, al
    pop rbx
    ret

; оценка частоты tsc с помощью pit (упрощенно)
; uint64_t asm_get_tsc_freq(void)
; возвращает приблизительную частоту tsc в гц
asm_get_tsc_freq:
    push rbx
    push r12
    push r13
    
    ; чтение начального tsc
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax        ; r12 = начальный tsc
    
    ; простая петля задержки (калибровано на ~10мс)
    mov r13, 10000000    ; счетчик циклов (аппроксимация зависит от архитектуры)
.delay_loop:
    dec r13
    jnz .delay_loop
    
    ; чтение конечного tsc
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    sub rax, r12        ; rax = разница tsc
    
    ; умножение на 100 для получения гц (т.к. ждали ~10мс)
    mov rcx, 100
    mul rcx             ; rax * 100 -> result in RAX
    
    pop r13
    pop r12
    pop rbx
    ret

; чтение конфигурационного пространства pci (если прямой доступ разрешен)
; uint32_t asm_read_pci_config(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg)
asm_read_pci_config:
    ; не используется на современном linux (вместо этого /sys/bus/pci)
    ; оставлено для справки по bare-metal сценариям
    xor eax, eax
    ret

; операции ввода-вывода через порты (для устаревшего доступа к железу)
; uint8_t asm_inb(uint16_t port)
global asm_inb
asm_inb:
    mov edx, edi
    xor eax, eax
    in al, dx
    ret

; void asm_outb(uint16_t port, uint8_t value)
global asm_outb
asm_outb:
    mov edx, edi
    mov eax, esi
    out dx, al
    ret

; uint16_t asm_inw(uint16_t port)
global asm_inw
asm_inw:
    mov edx, edi
    xor eax, eax
    in ax, dx
    ret

; void asm_outw(uint16_t port, uint16_t value)
global asm_outw
asm_outw:
    mov edx, edi
    mov eax, esi
    out dx, ax
    ret

; uint32_t asm_inl(uint16_t port)
global asm_inl
asm_inl:
    mov edx, edi
    xor eax, eax
    in eax, dx
    ret

; void asm_outl(uint16_t port, uint32_t value)
global asm_outl
asm_outl:
    mov edx, edi
    mov eax, esi
    out dx, eax
    ret
