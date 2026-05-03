; Additional hardware access assembly routines
; x86_64 Linux NASM syntax

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
    test edx, (1 << 26)    ; SSE2 bit
    setnz al
    movzx eax, al
    pop rbx
    ret

; int asm_check_avx(void)
asm_check_avx:
    push rbx
    mov eax, 1
    cpuid
    test ecx, (1 << 28)    ; AVX bit
    setnz al
    movzx eax, al
    pop rbx
    ret

; Estimate TSC frequency using PIT (simplified)
; uint64_t asm_get_tsc_freq(void)
; Returns approximate TSC frequency in Hz
asm_get_tsc_freq:
    push rbx
    push r12
    push r13
    
    ; Read initial TSC
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax        ; r12 = start TSC
    
    ; Simple delay loop (calibrated for roughly 10ms)
    mov r13, 10000000   ; Loop count (architecture dependent approximation)
.delay_loop:
    dec r13
    jnz .delay_loop
    
    ; Read final TSC
    rdtsc
    shl rdx, 32
    or rax, rdx
    
    sub rax, r12        ; rax = TSC delta
    
    ; Multiply by 100 to get Hz (since we waited ~10ms)
    mov rcx, 100
    mul rcx             ; rax * 100 -> result in RAX
    
    pop r13
    pop r12
    pop rbx
    ret

; Read PCI configuration space (if direct access is enabled)
; uint32_t asm_read_pci_config(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg)
asm_read_pci_config:
    ; Not used on modern Linux (uses /sys/bus/pci instead)
    ; Kept as reference for bare-metal scenarios
    xor eax, eax
    ret

; Port I/O operations (for legacy hardware access)
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
