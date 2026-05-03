; модуль глубокого сканирования железа
; низкоуровневая инспекция на ассемблере x86_64
; разработан быть легким и ненавязчивым

section .text

; сканирование точки входа smbios/dmi
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

; структура точки входа smbios
; точка входа smbios может быть найдена по адресам:
; - 0x000F0000 - 0x000FFFFF (физическая память)
; - или используя таблицы прошивки через /sys/firmware/dmi

; void asm_scan_smbios_entry(uint64_t *out_addr, uint32_t *out_len)
; поиск сигнатуры smbios в регионе прошивки
asm_scan_smbios_entry:
    push rbx
    push r12
    push r13
    
    mov r12, rdi        ; указатель на выходной адрес
    mov r13, rsi        ; указатель на выходную длину
    
    ; используем cpuid для проверки безопасности доступа к прошивке
    mov eax, 1
    cpuid
    
    ; возвращаем 0 (вместо этого используем /sys - безопаснее)
    mov qword [r12], 0
    mov dword [r13], 0
    
    pop r13
    pop r12
    pop rbx
    ret

; uint64_t asm_get_acpi_rsdp(void)
; возвращает адрес acpi rsdp (указатель на корневое описание системы)
; или 0 если недоступно (различия uefi vs bios)
asm_get_acpi_rsdp:
    xor rax, rax
    ; реальная реализация должна искать:
; 1. ebda (расширенная область данных bios) 0x40E
    ; 2. 0x000E0000 - 0x000FFFFF (bios rom)
    ; 3. таблица системы uefi (если загрузка через uefi)
    
    ; для безопасности возвращаем 0 - используем /sys/firmware/acpi/tables
    ret

; int asm_get_pci_config_space(uint8_t bus, uint8_t dev, uint8_t func, 
;                              uint8_t reg, uint32_t *out_data)
; чтение конфигурационного пространства pci через порты cf8/cfc
; примечание: современный linux блокирует прямой порт i/o, используйте /sys/bus/pci
asm_get_pci_config_space:
    push rbx
    
    ; сборка адреса конфигурации pci
    ; биты 31:24 = зарезервировано (1)
    ; биты 23:16 = шина
    ; биты 15:11 = устройство
    ; биты 10:8  = функция
    ; биты 7:0   = регистр (но выравниваем до 4 байт)
    
    mov eax, 0x80000000     ; бит включения (31)
    movzx ebx, dil          ; шина
    shl ebx, 16
    or eax, ebx
    movzx ebx, sil          ; устройство
    shl ebx, 11
    or eax, ebx
    movzx ebx, dl           ; функция
    shl ebx, 8
    or eax, ebx
    
    ; это требует root и iopl - linux ограничивает это
    ; возвращаем -1 чтобы указать "используйте /sys/bus/pci"
    mov eax, -1
    
    pop rbx
    ret

; uint32_t asm_get_cpu_microcode(void)
; возвращает версию микрокода процессора через msr 0x8b
asm_get_cpu_microcode:
    push rbx
    
    ; проверка доступности msr (бит 5 edx в cpuid)
    mov eax, 1
    cpuid
    test edx, (1 << 5)
    jz .no_msr
    
    ; чтение msr IA32_BIOS_SIGN_ID (0x8b)
    mov ecx, 0x8B
    rdmsr
    ; edx содержит версию микрокода
    mov eax, edx
    jmp .done
    
.no_msr:
    xor eax, eax
    
.done:
    pop rbx
    ret

; uint64_t asm_get_tsc_frequency(void)
; оценивает частоту tsc используя cpuid или калибровку
asm_get_tsc_frequency:
    push rbx
    push r12
    
    ; пробуем cpuid leaf 0x15 (частота tsc на новых intel)
    mov eax, 0x15
    cpuid
    
    ; если ebx != 0 и eax != 0, tsc = ecx * ebx / eax гц
    test ebx, ebx
    jz .use_calibration
    test eax, eax
    jz .use_calibration
    
    ; вычисление: частота_tsc = ecx * ebx / eax
    mov r12d, eax       ; сохраняем делитель
    mov eax, ecx
    xor edx, edx
    mul ebx             ; EDX:EAX = ECX * EBX
    div r12d            ; EAX = result
    
    ; конвертация в гц
    shl rdx, 32
    or rax, rdx
    jmp .done
    
.use_calibration:
    ; возвращаем 0 - пусть c код использует /proc/cpuinfo или калибрует
    xor rax, rax
    
.done:
    pop r12
    pop rbx
    ret

; int asm_check_hypervisor(void)
; возвращает тип гипервизора если запущено в виртуализации
asm_check_hypervisor:
    push rbx
    
    ; cpuid leaf 0x1 - проверка бита 31 ecx (гипервизор присутствует)
    mov eax, 1
    cpuid
    test ecx, (1 << 31)
    jz .not_virtual
    
    ; получение id вендора гипервизора через leaf 0x40000000
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
; получает полные флаги фич процессора
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
    
    ; стандартные фичи (cpuid leaf 1)
    mov eax, 1
    cpuid
    mov [r12], ecx
    mov [r13], edx
    
    ; расширенные фичи (cpuid leaf 7, subleaf 0)
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
; возвращает тайминги памяти если доступно (через msr или smbios)
asm_read_memory_timing:
    xor rax, rax
    ; тайминги памяти обычно не доступны напрямую через регистры cpu
    ; нужно парсить smbios тип 17 или использовать spd доступ через smbus
    ret

; int asm_get_cache_info(uint32_t level, uint32_t *size, uint32_t *ways, uint32_t *sets)
; получает информацию о кэше процессора через cpuid leaf 4
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
    
    ; cpuid leaf 4 - детерминированные параметры кэша
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
    
    ; проверка валидности кэша
    test al, 0x1F
    jz .invalid_cache
    
    ; вычисление размера
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
    
    ; вычисление полного размера
    mov eax, r8d       ; ways
    mul r9d            ; * partitions
    mul r10d           ; * line_size
    mul r11d           ; * sets
    
    mov [r13], eax     ; size
    mov [r14], r8d     ; ways
    mov [r15], r11d    ; sets
    
    mov eax, 1         ; успех
    jmp .done
    
.invalid_cache:
    mov dword [r13], 0
    mov dword [r14], 0
    mov dword [r15], 0
    xor eax, eax     ; неудача
    
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
