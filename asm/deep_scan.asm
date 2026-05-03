; Deep Hardware Scanning Module
; Low-level hardware inspection using x86_64 assembly
; Designed to be lightweight and non-intrusive

section .text

; SMBIOS/DMI Entry Point Scan
global asm_scan_smbios_entry
global asm_read_smbios_structure
global asm_get_acpi_rsdp
global asm_get_pci_config_space
global asm_read_pci_bios
global asm_get_cpu_microcode
global asm_get_tsc_frequency
global asm_check_hypervisor
global asm_get_cpuid_features
global asm_get_cache_info

; SMBIOS Entry Point structure
; The SMBIOS entry point can be found at:
; - 0x000F0000 - 0x000FFFFF (physical memory)
; - Or using firmware tables via /sys/firmware/dmi

; void asm_scan_smbios_entry(uint64_t *out_addr, uint32_t *out_len)
; Searches for SMBIOS signature in firmware region
asm_scan_smbios_entry:
    push rbx
    push r12
    push r13
    
    mov r12, rdi        ; out_addr pointer
    mov r13, rsi        ; out_len pointer
    
    ; Use CPUID to check if we can safely access firmware
    mov eax, 1
    cpuid
    
    ; Return 0 (use /sys interface instead - safer)
    mov qword [r12], 0
    mov dword [r13], 0
    
    pop r13
    pop r12
    pop rbx
    ret

; uint64_t asm_get_acpi_rsdp(void)
; Returns address of ACPI RSDP (Root System Description Pointer)
; or 0 if not available (UEFI vs BIOS differences)
asm_get_acpi_rsdp:
    xor rax, rax
    ; Real implementation would search:
; 1. EBDA (Extended BIOS Data Area) 0x40E
    ; 2. 0x000E0000 - 0x000FFFFF (BIOS ROM)
    ; 3. UEFI system table (if booted via UEFI)
    
    ; For safety, return 0 - use /sys/firmware/acpi/tables instead
    ret

; int asm_get_pci_config_space(uint8_t bus, uint8_t dev, uint8_t func, 
;                              uint8_t reg, uint32_t *out_data)
; Reads PCI configuration space via CF8/CFC ports
; Note: Modern Linux blocks direct port I/O, use /sys/bus/pci instead
asm_get_pci_config_space:
    push rbx
    
    ; Build PCI config address
    ; bits 31:24 = reserved (1)
    ; bits 23:16 = bus
    ; bits 15:11 = device
    ; bits 10:8  = function
    ; bits 7:0   = register (but we align to 4 bytes)
    
    mov eax, 0x80000000     ; Enable bit (31)
    movzx ebx, dil          ; bus
    shl ebx, 16
    or eax, ebx
    movzx ebx, sil          ; device
    shl ebx, 11
    or eax, ebx
    movzx ebx, dl           ; function
    shl ebx, 8
    or eax, ebx
    
    ; This requires root and iopl - Linux restricts this
    ; Return -1 to indicate "use /sys/bus/pci instead"
    mov eax, -1
    
    pop rbx
    ret

; uint32_t asm_get_cpu_microcode(void)
; Returns CPU microcode revision via MSR 0x8B
asm_get_cpu_microcode:
    push rbx
    
    ; Check if MSR is available (CPUID bit 5 of EDX)
    mov eax, 1
    cpuid
    test edx, (1 << 5)
    jz .no_msr
    
    ; Read IA32_BIOS_SIGN_ID MSR (0x8B)
    mov ecx, 0x8B
    rdmsr
    ; EDX contains microcode revision
    mov eax, edx
    jmp .done
    
.no_msr:
    xor eax, eax
    
.done:
    pop rbx
    ret

; uint64_t asm_get_tsc_frequency(void)
; Estimates TSC frequency using CPUID or calibration
asm_get_tsc_frequency:
    push rbx
    push r12
    
    ; Try CPUID leaf 0x15 (TSC frequency on newer Intel CPUs)
    mov eax, 0x15
    cpuid
    
    ; If EBX != 0 and EAX != 0, TSC = ECX * EBX / EAX Hz
    test ebx, ebx
    jz .use_calibration
    test eax, eax
    jz .use_calibration
    
    ; Calculate: TSC_freq = ECX * EBX / EAX
    mov r12d, eax       ; save divisor
    mov eax, ecx
    xor edx, edx
    mul ebx             ; EDX:EAX = ECX * EBX
    div r12d            ; EAX = result
    
    ; Convert to Hz
    shl rdx, 32
    or rax, rdx
    jmp .done
    
.use_calibration:
    ; Return 0 - let C code use /proc/cpuinfo or calibrate
    xor rax, rax
    
.done:
    pop r12
    pop rbx
    ret

; int asm_check_hypervisor(void)
; Returns hypervisor type if running virtualized
asm_check_hypervisor:
    push rbx
    
    ; CPUID leaf 0x1 - check ECX bit 31 (Hypervisor Present)
    mov eax, 1
    cpuid
    test ecx, (1 << 31)
    jz .not_virtual
    
    ; Get hypervisor vendor ID via leaf 0x40000000
    mov eax, 0x40000000
    cpuid
    
    ; EBX, ECX, EDX contain 12-character vendor string
    ; Common: "KVMKVMKVM\0\0\0", "Microsoft Hv", "VMwareVMware", "XenVMMXenVMM"
    
    mov eax, 1
    jmp .done
    
.not_virtual:
    xor eax, eax
    
.done:
    pop rbx
    ret

; void asm_get_cpuid_features(uint32_t *features_ecx, uint32_t *features_edx, 
;                             uint32_t *ext_features_ecx, uint32_t *ext_features_edx)
; Gets comprehensive CPU feature flags
asm_get_cpuid_features:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi        ; features_ecx
    mov r13, rsi        ; features_edx
    mov r14, rdx        ; ext_features_ecx
    mov r15, rcx        ; ext_features_edx
    
    ; Standard features (CPUID leaf 1)
    mov eax, 1
    cpuid
    mov [r12], ecx
    mov [r13], edx
    
    ; Extended features (CPUID leaf 7, subleaf 0)
    mov eax, 7
    xor ecx, ecx
    cpuid
    mov [r14], ecx
    mov [r15], edx
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; uint64_t asm_read_memory_timing(void)
; Returns memory timing info if available (via MSR or SMBIOS)
asm_read_memory_timing:
    xor rax, rax
    ; Memory timing is usually not directly accessible via CPU registers
    ; Would need to parse SMBIOS Type 17 or use SPD access via SMBus
    ret

; int asm_get_cache_info(uint32_t level, uint32_t *size, uint32_t *ways, uint32_t *sets)
; Gets CPU cache information via CPUID leaf 4
asm_get_cache_info:
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12d, edi       ; level (0-indexed)
    mov r13, rsi        ; size pointer
    mov r14, rdx        ; ways pointer
    mov r15, rcx        ; sets pointer
    
    ; CPUID leaf 4 - Deterministic Cache Parameters
    mov eax, 4
    mov ecx, r12d
    cpuid
    
    ; EAX bits 4:0 = Cache Type (0=None, 1=Data, 2=Instruction, 3=Unified)
    ; EAX bits 7:5 = Cache Level
    ; EAX bits 31:14 = Sets (num_sets + 1)
    ; EBX bits 11:0 = Line Size (line_size + 1) * bytes
    ; EBX bits 21:12 = Physical Line partitions (partitions + 1)
    ; EBX bits 31:22 = Ways of associativity (ways + 1)
    ; ECX bits 31:0 = Number of sets (sets + 1)
    
    ; Check if valid cache
    test al, 0x1F
    jz .invalid_cache
    
    ; Calculate size
    ; size = ways * partitions * line_size * sets
    mov r8d, ebx
    shr r8d, 22        ; ways - 1
    inc r8d            ; ways
    
    mov r9d, ebx
    shr r9d, 12
    and r9d, 0x3FF     ; partitions - 1
    inc r9d            ; partitions
    
    mov r10d, ebx
    and r10d, 0xFFF    ; line_size - 1
    inc r10d           ; line_size
    
    mov r11d, ecx      ; sets
    inc r11d
    
    ; Calculate total size
    mov eax, r8d       ; ways
    mul r9d            ; * partitions
    mul r10d           ; * line_size
    mul r11d           ; * sets
    
    mov [r13], eax     ; size
    mov [r14], r8d     ; ways
    mov [r15], r11d    ; sets
    
    mov eax, 1         ; success
    jmp .done
    
.invalid_cache:
    mov dword [r13], 0
    mov dword [r14], 0
    mov dword [r15], 0
    xor eax, eax     ; failure
    
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
