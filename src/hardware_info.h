#ifndef HARDWARE_INFO_H
#define HARDWARE_INFO_H

#include <stdint.h>

// структура результатов cpuid
typedef struct {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuid_result_t;

// функции информации об оборудовании
char* hardware_get_cpu_serial(void);
char* hardware_get_cpuid_info(void);
char* hardware_get_memory_info(void);
char* hardware_get_dmi_info(void);
char* hardware_get_tpm_info(void);
char* hardware_get_acpi_info(void);

// низкоуровневый доступ (реализации на asm)
extern uint64_t asm_read_msr(uint32_t msr);
extern void asm_cpuid(uint32_t leaf, uint32_t subleaf, cpuid_result_t *result);
extern int asm_has_rdtscp(void);
extern uint64_t asm_read_tsc(void);

// глубокое сканирование железа (новый модуль asm)
extern uint32_t asm_get_cpu_microcode(void);
extern uint64_t asm_get_tsc_frequency(void);
extern int asm_check_hypervisor(void);
extern void asm_get_cpuid_features(uint32_t *features_ecx, uint32_t *features_edx, 
                                   uint32_t *ext_features_ecx, uint32_t *ext_features_edx);
extern int asm_get_cache_info(uint32_t level, uint32_t *size, uint32_t *ways, uint32_t *sets);

// доступ к smbios/dmi
char* hardware_read_smbios(void);
char* hardware_get_deep_scan_info(void);

// информация о secure boot и uefi
char* hardware_get_uefi_info(void);

#endif // hardware_info_h
