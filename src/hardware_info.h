#ifndef HARDWARE_INFO_H
#define HARDWARE_INFO_H

#include <stdint.h>

// CPUID results structure
typedef struct {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuid_result_t;

// Hardware info functions
char* hardware_get_cpu_serial(void);
char* hardware_get_cpuid_info(void);
char* hardware_get_memory_info(void);
char* hardware_get_dmi_info(void);
char* hardware_get_tpm_info(void);
char* hardware_get_acpi_info(void);

// Low-level access (ASM implementations)
extern uint64_t asm_read_msr(uint32_t msr);
extern void asm_cpuid(uint32_t leaf, uint32_t subleaf, cpuid_result_t *result);
extern int asm_has_rdtscp(void);
extern uint64_t asm_read_tsc(void);

// Deep hardware scanning (new ASM module)
extern uint32_t asm_get_cpu_microcode(void);
extern uint64_t asm_get_tsc_frequency(void);
extern int asm_check_hypervisor(void);
extern void asm_get_cpuid_features(uint32_t *features_ecx, uint32_t *features_edx, 
                                   uint32_t *ext_features_ecx, uint32_t *ext_features_edx);
extern int asm_get_cache_info(uint32_t level, uint32_t *size, uint32_t *ways, uint32_t *sets);

// SMBIOS/DMI access
char* hardware_read_smbios(void);
char* hardware_get_deep_scan_info(void);

// Secure boot and UEFI info
char* hardware_get_uefi_info(void);

#endif // HARDWARE_INFO_H
