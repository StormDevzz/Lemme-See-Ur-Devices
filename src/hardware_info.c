/*
 * Hardware Info Module
 * Deep hardware inspection using C and ASM integration
 */

#include "hardware_info.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

// External assembly functions
extern void asm_get_cpu_vendor(char *buffer);
extern void asm_get_cpu_brand(char *buffer);
extern uint32_t asm_get_cpu_signature(void);
extern int asm_cpu_has_feature(uint32_t feature);

char* hardware_get_cpu_serial(void) {
    char *buffer = malloc(4096);
    if (!buffer) return NULL;
    
    strcpy(buffer, "CPU Serial Number Analysis\n");
    strcat(buffer, "===========================\n\n");
    
    // Try to read from CPUID (PSN - Processor Serial Number)
    cpuid_result_t result;
    asm_cpuid(1, 0, &result);
    
    char vendor[16] = {0};
    asm_get_cpu_vendor(vendor);
    
    snprintf(buffer + strlen(buffer), 1024,
             "CPU Vendor: %s\n"
             "CPU Signature: 0x%08X\n"
             "Family: %d, Model: %d, Stepping: %d\n\n",
             vendor,
             asm_get_cpu_signature(),
             (result.eax >> 8) & 0xF,
             (result.eax >> 4) & 0xF,
             result.eax & 0xF);
    
    // Check for PSN support (Pentium III era feature, mostly removed now)
    asm_cpuid(1, 0, &result);
    int psn_supported = (result.edx >> 18) & 1;
    
    if (psn_supported) {
        asm_cpuid(3, 0, &result);
        snprintf(buffer + strlen(buffer), 512,
                 "Processor Serial Number:\n"
                 "  High: 0x%08X\n"
                 "  Low:  0x%08X\n",
                 result.ecx, result.edx);
    } else {
        strcat(buffer, "CPU Serial Number (PSN) not available on this processor.\n");
        strcat(buffer, "Modern CPUs do not expose serial numbers via CPUID for privacy.\n\n");
    }
    
    // Alternative: Machine ID from various sources
    strcat(buffer, "Alternative Identifiers:\n");
    
    // Try to get machine ID
    FILE *fp = fopen("/etc/machine-id", "r");
    if (fp) {
        char mid[64];
        if (fgets(mid, sizeof(mid), fp)) {
            mid[strcspn(mid, "\n")] = 0;
            snprintf(buffer + strlen(buffer), 256, "  Machine ID: %s\n", mid);
        }
        fclose(fp);
    }
    
    // DMI UUID
    fp = popen("cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo 'N/A'", "r");
    if (fp) {
        char uuid[64];
        if (fgets(uuid, sizeof(uuid), fp)) {
            uuid[strcspn(uuid, "\n")] = 0;
            snprintf(buffer + strlen(buffer), 256, "  DMI UUID: %s\n", uuid);
        }
        pclose(fp);
    }
    
    return buffer;
}

char* hardware_get_cpuid_info(void) {
    char *buffer = malloc(8192);
    if (!buffer) return NULL;
    
    strcpy(buffer, "CPUID Detailed Information\n");
    strcat(buffer, "==========================\n\n");
    
    cpuid_result_t result;
    
    // Vendor ID
    char vendor[16] = {0};
    asm_get_cpu_vendor(vendor);
    snprintf(buffer + strlen(buffer), 512, "Vendor ID: %s\n\n", vendor);
    
    // Brand string
    char brand[64] = {0};
    asm_get_cpu_brand(brand);
    snprintf(buffer + strlen(buffer), 512, "Brand: %s\n\n", brand);
    
    // CPUID leaf 1 - Processor Info
    asm_cpuid(1, 0, &result);
    snprintf(buffer + strlen(buffer), 1024,
             "Processor Info (CPUID Leaf 1):\n"
             "  EAX: 0x%08X\n"
             "    Stepping: %d\n"
             "    Model: %d\n"
             "    Family: %d\n"
             "    Processor Type: %d\n"
             "    Extended Model: %d\n"
             "    Extended Family: %d\n"
             "  EBX: 0x%08X\n"
             "    Brand Index: %d\n"
             "    CLFLUSH line size: %d bytes\n"
             "    Max IDs: %d\n"
             "    Initial APIC ID: %d\n"
             "  ECX: 0x%08X\n"
             "  EDX: 0x%08X\n\n",
             result.eax,
             result.eax & 0xF,
             (result.eax >> 4) & 0xF,
             (result.eax >> 8) & 0xF,
             (result.eax >> 12) & 0x3,
             (result.eax >> 16) & 0xF,
             (result.eax >> 20) & 0xFF,
             result.ebx,
             result.ebx & 0xFF,
             ((result.ebx >> 8) & 0xFF) * 8,
             (result.ebx >> 16) & 0xFF,
             (result.ebx >> 24) & 0xFF,
             result.ecx,
             result.edx);
    
    // Feature flags
    strcat(buffer, "Feature Flags:\n");
    
    struct {
        uint32_t reg;
        int bit;
        const char *name;
    } features[] = {
        {result.edx, 0, "FPU"},
        {result.edx, 4, "TSC"},
        {result.edx, 5, "MSR"},
        {result.edx, 6, "PAE"},
        {result.edx, 9, "APIC"},
        {result.edx, 13, "CMOV"},
        {result.edx, 15, "CMOVcc"},
        {result.edx, 23, "MMX"},
        {result.edx, 25, "SSE"},
        {result.edx, 26, "SSE2"},
        {result.edx, 28, "HTT"},
        {result.ecx, 0, "SSE3"},
        {result.ecx, 9, "SSSE3"},
        {result.ecx, 19, "SSE4.1"},
        {result.ecx, 20, "SSE4.2"},
        {result.ecx, 28, "AVX"},
        {0, 0, NULL}
    };
    
    for (int i = 0; features[i].name; i++) {
        int supported = (features[i].reg >> features[i].bit) & 1;
        snprintf(buffer + strlen(buffer), 256, "  [%s] %s\n",
                 supported ? "X" : " ",
                 features[i].name);
    }
    
    // Check extended features
    asm_cpuid(0x80000000, 0, &result);
    if (result.eax >= 0x80000001) {
        asm_cpuid(0x80000001, 0, &result);
        strcat(buffer, "\nExtended Features:\n");
        
        const char *ext_features[] = {
            "LM (Long Mode/64-bit)",
            "3DNow!",
            "3DNow! Extended"
        };
        int ext_bits[] = {29, 31, 30};
        
        for (int i = 0; i < 3; i++) {
            int supported = (result.edx >> ext_bits[i]) & 1;
            snprintf(buffer + strlen(buffer), 256, "  [%s] %s\n",
                     supported ? "X" : " ",
                     ext_features[i]);
        }
    }
    
    return buffer;
}

char* hardware_get_memory_info(void) {
    char *buffer = malloc(4096);
    if (!buffer) return NULL;
    
    strcpy(buffer, "Memory Information\n");
    strcat(buffer, "===================\n\n");
    
    FILE *fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Mem", 3) == 0 ||
                strncmp(line, "Swap", 4) == 0 ||
                strncmp(line, "Huge", 4) == 0 ||
                strncmp(line, "DirectMap", 9) == 0) {
                strncat(buffer, line, 4096 - strlen(buffer) - 1);
            }
        }
        fclose(fp);
    }
    
    // Physical memory layout
    strcat(buffer, "\n--- Physical Memory Layout ---\n");
    
    fp = popen("cat /proc/iomem 2>/dev/null | grep -i 'ram\\|memory' | head -10", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(buffer, line, 4096 - strlen(buffer) - 1);
        }
        pclose(fp);
    }
    
    // DIMM info via DMI if available
    strcat(buffer, "\n--- DIMM Information ---\n");
    
    fp = popen("dmidecode -t memory 2>/dev/null | grep -A3 'Memory Device' | head -30 || echo 'dmidecode not available (need root)'", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(buffer, line, 4096 - strlen(buffer) - 1);
        }
        pclose(fp);
    }
    
    return buffer;
}

char* hardware_get_dmi_info(void) {
    char *buffer = malloc(8192);
    if (!buffer) return NULL;
    
    strcpy(buffer, "DMI/SMBIOS Information\n");
    strcat(buffer, "=======================\n\n");
    
    // System info from sysfs
    const char *dmi_files[] = {
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/product_version",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/board_name",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/bios_version",
        "/sys/class/dmi/id/bios_date"
    };
    
    const char *dmi_labels[] = {
        "System Vendor",
        "Product Name",
        "Product Version",
        "Board Vendor",
        "Board Name",
        "BIOS Vendor",
        "BIOS Version",
        "BIOS Date"
    };
    
    for (int i = 0; i < 8; i++) {
        FILE *fp = fopen(dmi_files[i], "r");
        if (fp) {
            char value[256];
            if (fgets(value, sizeof(value), fp)) {
                value[strcspn(value, "\n")] = 0;
                snprintf(buffer + strlen(buffer), 512, "%-16s: %s\n", dmi_labels[i], value);
            }
            fclose(fp);
        }
    }
    
    // Chassis info
    FILE *fp = fopen("/sys/class/dmi/id/chassis_type", "r");
    if (fp) {
        int type;
        if (fscanf(fp, "%d", &type) == 1) {
            const char *chassis_types[] = {
                "Other", "Unknown", "Desktop", "Low Profile Desktop",
                "Pizza Box", "Mini Tower", "Tower", "Portable",
                "Laptop", "Notebook", "Hand Held", "Docking Station",
                "All in One", "Sub Notebook", "Space-saving",
                "Lunch Box", "Main Server Chassis", "Expansion Chassis",
                "SubChassis", "Bus Expansion Chassis", "Peripheral Chassis",
                "RAID Chassis", "Rack Mount Chassis", "Sealed-case PC",
                "Multi-system chassis", "Compact PCI", "Advanced TCA",
                "Blade", "Blade Enclosure", "Tablet", "Convertible",
                "Detachable", "IoT Gateway", "Embedded PC",
                "Mini PC", "Stick PC"
            };
            if (type > 0 && type <= 36) {
                snprintf(buffer + strlen(buffer), 512, "%-16s: %d (%s)\n", "Chassis Type", type, chassis_types[type]);
            }
        }
        fclose(fp);
    }
    
    return buffer;
}

char* hardware_get_uefi_info(void) {
    char *buffer = malloc(4096);
    if (!buffer) return NULL;
    
    strcpy(buffer, "UEFI/Secure Boot Information\n");
    strcat(buffer, "=============================\n\n");
    
    // Check for EFI variables
    FILE *fp = fopen("/sys/firmware/efi/fw_platform_size", "r");
    if (fp) {
        int size;
        if (fscanf(fp, "%d", &size) == 1) {
            snprintf(buffer + strlen(buffer), 512, "EFI Platform: %d-bit\n", size);
        }
        fclose(fp);
    }
    
    // Secure boot status
    fp = fopen("/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data", "rb");
    if (!fp) {
        fp = fopen("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", "rb");
    }
    if (fp) {
        unsigned char data[16];
        size_t read = fread(data, 1, sizeof(data), fp);
        if (read >= 5) {
            int secure_boot = data[4];
            snprintf(buffer + strlen(buffer), 512, "Secure Boot: %s\n", secure_boot ? "Enabled" : "Disabled");
        }
        fclose(fp);
    } else {
        strcat(buffer, "Secure Boot: Not available (Legacy BIOS or missing permissions)\n");
    }
    
    // EFI runtime services
    if (access("/sys/firmware/efi/runtime", F_OK) == 0) {
        strcat(buffer, "EFI Runtime Services: Available\n");
    }
    
    // Boot entries
    strcat(buffer, "\n--- Boot Entries ---\n");
    
    DIR *dir = opendir("/sys/firmware/efi/efivars");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, "Boot")) {
                snprintf(buffer + strlen(buffer), 512, "  %s\n", entry->d_name);
            }
        }
        closedir(dir);
    }
    
    return buffer;
}

char* hardware_get_tpm_info(void) {
    char *buffer = malloc(4096);
    if (!buffer) return NULL;
    
    strcpy(buffer, "TPM Information\n");
    strcat(buffer, "================\n\n");
    
    // Check for TPM devices
    DIR *dir = opendir("/sys/class/tpm");
    if (dir) {
        struct dirent *entry;
        int found = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            
            found = 1;
            snprintf(buffer + strlen(buffer), 512, "TPM Device: %s\n", entry->d_name);
            
            char path[512];
            snprintf(path, sizeof(path), "/sys/class/tpm/%s/tpm_version_major", entry->d_name);
            FILE *fp = fopen(path, "r");
            if (fp) {
                int version;
                if (fscanf(fp, "%d", &version) == 1) {
                    snprintf(buffer + strlen(buffer), 512, "  Version: TPM %d.0\n", version);
                }
                fclose(fp);
            }
            
            snprintf(path, sizeof(path), "/sys/class/tpm/%s/device/enabled", entry->d_name);
            fp = fopen(path, "r");
            if (fp) {
                int enabled;
                if (fscanf(fp, "%d", &enabled) == 1) {
                    snprintf(buffer + strlen(buffer), 512, "  Status: %s\n", enabled ? "Enabled" : "Disabled");
                }
                fclose(fp);
            }
        }
        closedir(dir);
        
        if (!found) {
            strcat(buffer, "No TPM devices found.\n");
        }
    } else {
        strcat(buffer, "TPM sysfs interface not available.\n");
    }
    
    // Also check TPM2
    if (access("/dev/tpm0", F_OK) == 0) {
        snprintf(buffer + strlen(buffer), 512, "\nTPM device node: /dev/tpm0 exists\n");
    }
    if (access("/dev/tpmrm0", F_OK) == 0) {
        snprintf(buffer + strlen(buffer), 512, "TPM resource manager: /dev/tpmrm0 exists\n");
    }
    
    return buffer;
}

char* hardware_get_acpi_info(void) {
    char *buffer = malloc(4096);
    if (!buffer) return NULL;
    
    strcpy(buffer, "ACPI Information\n");
    strcat(buffer, "=================\n\n");
    
    // ACPI tables
    DIR *dir = opendir("/sys/firmware/acpi/tables");
    if (dir) {
        strcat(buffer, "Available ACPI Tables:\n");
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            snprintf(buffer + strlen(buffer), 512, "  %s\n", entry->d_name);
        }
        closedir(dir);
    }
    
    // ACPI interrupt info
    FILE *fp = fopen("/sys/firmware/acpi/interrupts/sci", "r");
    if (fp) {
        char value[64];
        if (fgets(value, sizeof(value), fp)) {
            snprintf(buffer + strlen(buffer), 512, "\nSCI Interrupts: %s", value);
        }
        fclose(fp);
    }
    
    return buffer;
}

char* hardware_get_deep_scan_info(void) {
    char *buffer = malloc(8192);
    if (!buffer) return NULL;
    FILE *fp;
    
    strcpy(buffer, "Deep Hardware Scan (Assembly-enhanced)\n");
    strcat(buffer, "======================================\n\n");
    
    // CPU Microcode version via MSR
    uint32_t microcode = asm_get_cpu_microcode();
    if (microcode > 0) {
        snprintf(buffer + strlen(buffer), 256, "CPU Microcode: 0x%08X\n", microcode);
    } else {
        strcat(buffer, "CPU Microcode: Not available (MSR access restricted)\n");
    }
    
    // Hypervisor detection
    int hypervisor = asm_check_hypervisor();
    if (hypervisor) {
        strcat(buffer, "Virtualization: Detected (Running in VM)\n");
        
        // Try to identify hypervisor
        uint32_t leaf_ebx, leaf_ecx, leaf_edx;
        cpuid_result_t res;
        asm_cpuid(0x40000000, 0, &res);
        leaf_ebx = res.ebx;
        leaf_ecx = res.ecx;
        leaf_edx = res.edx;
        
        char hv_name[13] = {0};
        memcpy(hv_name, &leaf_ebx, 4);
        memcpy(hv_name + 4, &leaf_ecx, 4);
        memcpy(hv_name + 8, &leaf_edx, 4);
        hv_name[12] = '\0';
        
        snprintf(buffer + strlen(buffer), 256, "Hypervisor ID: %s\n", hv_name);
        
        if (strstr(hv_name, "VMware")) {
            strcat(buffer, "  Type: VMware virtualization\n");
        } else if (strstr(hv_name, "KVM")) {
            strcat(buffer, "  Type: KVM/QEMU virtualization\n");
        } else if (strstr(hv_name, "Microsoft")) {
            strcat(buffer, "  Type: Hyper-V virtualization\n");
        } else if (strstr(hv_name, "Xen")) {
            strcat(buffer, "  Type: Xen virtualization\n");
        } else if (strstr(hv_name, "VBox")) {
            strcat(buffer, "  Type: VirtualBox\n");
        }
    } else {
        strcat(buffer, "Virtualization: Not detected (Running on bare metal)\n");
    }
    
    // CPUID Features
    strcat(buffer, "\n--- CPU Features ---\n");
    uint32_t feat_ecx = 0, feat_edx = 0, ext_feat_ecx = 0, ext_feat_edx = 0;
    asm_get_cpuid_features(&feat_ecx, &feat_edx, &ext_feat_ecx, &ext_feat_edx);
    
    // Check for important features
    if (feat_ecx & (1 << 28)) strcat(buffer, "AVX: Supported\n");
    if (feat_ecx & (1 << 25)) strcat(buffer, "AES-NI: Supported\n");
    if (feat_ecx & (1 << 30)) strcat(buffer, "RDRAND: Supported\n");
    if (ext_feat_ecx & (1 << 5)) strcat(buffer, "AVX2: Supported\n");
    if (ext_feat_edx & (1 << 18)) strcat(buffer, "RDSEED: Supported\n");
    
    // Cache information
    strcat(buffer, "\n--- Cache Information ---\n");
    for (int level = 0; level < 4; level++) {
        uint32_t size = 0, ways = 0, sets = 0;
        if (asm_get_cache_info(level, &size, &ways, &sets)) {
            const char *type_str = "";
            if (level == 0) type_str = "L1 Data";
            else if (level == 1) type_str = "L1 Instruction";
            else if (level == 2) type_str = "L2 Unified";
            else if (level == 3) type_str = "L3 Unified";
            
            snprintf(buffer + strlen(buffer), 256, "%s: %u KB, %u-way, %u sets\n", 
                     type_str, size / 1024, ways, sets);
        }
    }
    
    // TSC frequency estimate
    uint64_t tsc_freq = asm_get_tsc_frequency();
    if (tsc_freq > 0) {
        snprintf(buffer + strlen(buffer), 256, "\nTSC Frequency: ~%lu MHz\n", tsc_freq / 1000000);
    }
    
    // PCI scan summary
    strcat(buffer, "\n--- PCI Bus Scan Summary ---\n");
    fp = popen("lspci -nn 2>/dev/null | wc -l", "r");
    if (fp) {
        int pci_count = 0;
        if (fscanf(fp, "%d", &pci_count) == 1) {
            snprintf(buffer + strlen(buffer), 256, "PCI Devices: %d\n", pci_count);
        }
        pclose(fp);
    }
    
    // USB controller summary
    fp = popen("lsusb 2>/dev/null | grep -c 'Bus'", "r");
    if (fp) {
        int usb_count = 0;
        if (fscanf(fp, "%d", &usb_count) == 1) {
            snprintf(buffer + strlen(buffer), 256, "USB Devices: %d\n", usb_count);
        }
        pclose(fp);
    }
    
    // Thermal info
    strcat(buffer, "\n--- Thermal Information ---\n");
    DIR *dir = opendir("/sys/class/thermal");
    if (dir) {
        struct dirent *entry;
        int thermal_zones = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, "thermal_zone")) {
                thermal_zones++;
                char path[512], type[64];
                snprintf(path, sizeof(path), "/sys/class/thermal/%s/type", entry->d_name);
                FILE *tfp = fopen(path, "r");
                if (tfp) {
                    if (fgets(type, sizeof(type), tfp)) {
                        type[strcspn(type, "\n")] = 0;
                        // Get temperature
                        snprintf(path, sizeof(path), "/sys/class/thermal/%s/temp", entry->d_name);
                        FILE *temp_fp = fopen(path, "r");
                        if (temp_fp) {
                            int temp_millideg = 0;
                            if (fscanf(temp_fp, "%d", &temp_millideg) == 1) {
                                snprintf(buffer + strlen(buffer), 256, "%s: %.1f°C\n", 
                                         type, temp_millideg / 1000.0);
                            }
                            fclose(temp_fp);
                        }
                    }
                    fclose(tfp);
                }
            }
        }
        closedir(dir);
        if (thermal_zones == 0) {
            strcat(buffer, "No thermal zones available\n");
        }
    } else {
        strcat(buffer, "Thermal info not available\n");
    }
    
    return buffer;
}
