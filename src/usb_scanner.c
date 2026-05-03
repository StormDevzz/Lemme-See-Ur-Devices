/*
 * USB Scanner Module
 * Comprehensive USB device discovery and analysis
 */

#include "usb_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>

static struct udev *udev_ctx = NULL;
static struct udev_enumerate *enumerate = NULL;

int usb_scanner_init(void) {
    udev_ctx = udev_new();
    if (!udev_ctx) {
        return -1;
    }
    return 0;
}

void usb_scanner_cleanup(void) {
    if (enumerate) {
        udev_enumerate_unref(enumerate);
        enumerate = NULL;
    }
    if (udev_ctx) {
        udev_unref(udev_ctx);
        udev_ctx = NULL;
    }
}

static void get_usb_device_details(usb_device_info_t *info, struct udev_device *dev) {
    const char *val;
    
    memset(info, 0, sizeof(usb_device_info_t));
    
    val = udev_device_get_sysname(dev);
    if (val) strncpy(info->sysname, val, sizeof(info->sysname) - 1);
    
    val = udev_device_get_devnode(dev);
    if (val) strncpy(info->devnode, val, sizeof(info->devnode) - 1);
    
    val = udev_device_get_property_value(dev, "ID_VENDOR");
    if (val) strncpy(info->id_vendor, val, sizeof(info->id_vendor) - 1);
    
    val = udev_device_get_property_value(dev, "ID_VENDOR_ENC");
    if (!val) val = udev_device_get_property_value(dev, "ID_VENDOR");
    if (val) strncpy(info->vendor, val, sizeof(info->vendor) - 1);
    
    val = udev_device_get_property_value(dev, "ID_MODEL");
    if (val) strncpy(info->id_product, val, sizeof(info->id_product) - 1);
    
    val = udev_device_get_property_value(dev, "ID_MODEL_ENC");
    if (!val) val = udev_device_get_property_value(dev, "ID_MODEL");
    if (val) strncpy(info->model, val, sizeof(info->model) - 1);
    
    val = udev_device_get_property_value(dev, "ID_SERIAL");
    if (val) strncpy(info->serial, val, sizeof(info->serial) - 1);
    
    val = udev_device_get_property_value(dev, "BUSNUM");
    if (val) strncpy(info->busnum, val, sizeof(info->busnum) - 1);
    
    val = udev_device_get_property_value(dev, "DEVNUM");
    if (val) strncpy(info->devnum, val, sizeof(info->devnum) - 1);
    
    val = udev_device_get_property_value(dev, "ID_MANUFACTURER");
    if (val) strncpy(info->manufacturer, val, sizeof(info->manufacturer) - 1);
    
    val = udev_device_get_property_value(dev, "ID_PRODUCT");
    if (val) strncpy(info->product, val, sizeof(info->product) - 1);
    
    val = udev_device_get_property_value(dev, "SPEED");
    if (val) info->speed = atoi(val);
}

int usb_enumerate_devices(usb_device_info_t **devices, int *count) {
    if (!udev_ctx) return -1;
    
    enumerate = udev_enumerate_new(udev_ctx);
    udev_enumerate_add_match_subsystem(enumerate, "usb");
    udev_enumerate_scan_devices(enumerate);
    
    struct udev_list_entry *devices_list = udev_enumerate_get_list_entry(enumerate);
    struct udev_list_entry *entry;
    
    // Count devices
    *count = 0;
    udev_list_entry_foreach(entry, devices_list) {
        (*count)++;
    }
    
    if (*count == 0) {
        udev_enumerate_unref(enumerate);
        enumerate = NULL;
        *devices = NULL;
        return 0;
    }
    
    *devices = calloc(*count, sizeof(usb_device_info_t));
    if (!*devices) {
        udev_enumerate_unref(enumerate);
        enumerate = NULL;
        return -1;
    }
    
    int idx = 0;
    udev_list_entry_foreach(entry, devices_list) {
        const char *path = udev_list_entry_get_name(entry);
        struct udev_device *dev = udev_device_new_from_syspath(udev_ctx, path);
        if (dev) {
            get_usb_device_details(&(*devices)[idx], dev);
            udev_device_unref(dev);
            idx++;
        }
    }
    
    *count = idx;
    
    udev_enumerate_unref(enumerate);
    enumerate = NULL;
    
    return 0;
}

void usb_free_device_list(usb_device_info_t *devices, int count) {
    (void)count;
    free(devices);
}

char* usb_get_device_list(void) {
    usb_device_info_t *devices = NULL;
    int count = 0;
    
    if (usb_enumerate_devices(&devices, &count) < 0) {
        return strdup("Error: Failed to enumerate USB devices\n");
    }
    
    size_t buffer_size = 8192;
    char *buffer = malloc(buffer_size);
    if (!buffer) return NULL;
    
    snprintf(buffer, buffer_size, 
             "USB Device Analysis\n"
             "===================\n\n"
             "Found %d USB device(s)\n\n",
             count);
    
    for (int i = 0; i < count; i++) {
        char device_str[2048];
        char enhanced_serial[256] = {0};
        char manufacturer[256] = {0};
        char product[256] = {0};
        
        // Try to get more detailed info from sysfs
        char sysfs_path[512];
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/usb/devices/%s/serial", devices[i].sysname);
        FILE *sfp = fopen(sysfs_path, "r");
        if (sfp) {
            if (fgets(enhanced_serial, sizeof(enhanced_serial), sfp)) {
                enhanced_serial[strcspn(enhanced_serial, "\n")] = 0;
            }
            fclose(sfp);
        }
        
        // Get manufacturer
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/usb/devices/%s/manufacturer", devices[i].sysname);
        sfp = fopen(sysfs_path, "r");
        if (sfp) {
            if (fgets(manufacturer, sizeof(manufacturer), sfp)) {
                manufacturer[strcspn(manufacturer, "\n")] = 0;
            }
            fclose(sfp);
        }
        
        // Get product name
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/usb/devices/%s/product", devices[i].sysname);
        sfp = fopen(sysfs_path, "r");
        if (sfp) {
            if (fgets(product, sizeof(product), sfp)) {
                product[strcspn(product, "\n")] = 0;
            }
            fclose(sfp);
        }
        
        // Get additional attributes
        char version[32] = {0};
        char maxchild[32] = {0};
        
        // Detect device type (MTP, ADB, RNDIS, etc.)
        char device_type[128] = {0};
        char driver[64] = {0};
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/usb/devices/%s/driver", devices[i].sysname);
        char driver_link[512];
        ssize_t link_len = readlink(sysfs_path, driver_link, sizeof(driver_link) - 1);
        if (link_len > 0) {
            driver_link[link_len] = 0;
            char *driver_name = strrchr(driver_link, '/');
            if (driver_name) {
                strcpy(driver, driver_name + 1);
            }
        }
        
        // Check for common phone/device classes
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/usb/devices/%s/bDeviceClass", devices[i].sysname);
        sfp = fopen(sysfs_path, "r");
        char dev_class[16] = {0};
        if (sfp) {
            fgets(dev_class, sizeof(dev_class), sfp);
            fclose(sfp);
        }
        
        // Check interface class
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/usb/devices/%s:1.0/bInterfaceClass", devices[i].sysname);
        sfp = fopen(sysfs_path, "r");
        char if_class[16] = {0};
        if (sfp) {
            fgets(if_class, sizeof(if_class), sfp);
            fclose(sfp);
        }
        
        // Determine device type
        if (strstr(devices[i].model, "MTP") || strstr(product, "MTP") || 
            strstr(devices[i].model, "Android") || strstr(product, "Android")) {
            strcpy(device_type, " [PHONE-MTP/File Transfer]");
        } else if (strstr(driver, "usbnet") || strstr(driver, "rndis") || 
                   strstr(product, "RNDIS") || strstr(devices[i].model, "RNDIS")) {
            strcpy(device_type, " [PHONE-Tethering/RNDIS]");
        } else if (strstr(driver, "adb") || strstr(product, "ADB") || 
                   strstr(devices[i].model, "ADB")) {
            strcpy(device_type, " [PHONE-ADB Debug]");
        } else if (strstr(product, "iPhone") || strstr(devices[i].model, "iPhone")) {
            strcpy(device_type, " [iPhone]");
        } else if (strstr(product, "iPad") || strstr(devices[i].model, "iPad")) {
            strcpy(device_type, " [iPad]");
        } else if (strstr(product, "PTP") || strstr(devices[i].model, "PTP") ||
                   (strstr(if_class, "06") && strstr(if_class, "01"))) {
            strcpy(device_type, " [Camera/PTP Mode]");
        } else if (atoi(dev_class) == 9) {
            strcpy(device_type, " [USB Hub]");
        } else if (atoi(dev_class) == 8) {
            strcpy(device_type, " [Mass Storage]");
        } else if (driver[0] && strcmp(driver, "usb") != 0) {
            snprintf(device_type, sizeof(device_type), " [%s]", driver);
        }
        
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/usb/devices/%s/version", devices[i].sysname);
        sfp = fopen(sysfs_path, "r");
        if (sfp) {
            if (fgets(version, sizeof(version), sfp)) {
                version[strcspn(version, "\n")] = 0;
            }
            fclose(sfp);
        }
        
        snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/usb/devices/%s/maxchild", devices[i].sysname);
        sfp = fopen(sysfs_path, "r");
        if (sfp) {
            if (fgets(maxchild, sizeof(maxchild), sfp)) {
                maxchild[strcspn(maxchild, "\n")] = 0;
            }
            fclose(sfp);
        }
        
        snprintf(device_str, sizeof(device_str),
                 "[%d] Device: %s%s\n"
                 "    ├─ Vendor:     %s (ID: %s)\n"
                 "    ├─ Model:      %s (ID: %s)\n"
                 "    ├─ Serial:     %s\n"
                 "    ├─ Bus:        %s, Port: %s\n"
                 "    ├─ USB Ver:    %s\n"
                 "    ├─ Speed:      %d Mbps\n"
                 "    ├─ Ports:      %s\n"
                 "    └─ Node:       %s\n\n",
                 i + 1,
                 devices[i].sysname,
                 device_type,
                 manufacturer[0] ? manufacturer : (devices[i].vendor[0] ? devices[i].vendor : "Unknown"),
                 devices[i].id_vendor,
                 product[0] ? product : (devices[i].model[0] ? devices[i].model : "Unknown"),
                 devices[i].id_product,
                 enhanced_serial[0] ? enhanced_serial : (devices[i].serial[0] ? devices[i].serial : "N/A"),
                 devices[i].busnum,
                 devices[i].devnum,
                 version[0] ? version : "N/A",
                 devices[i].speed,
                 maxchild[0] ? maxchild : "N/A",
                 devices[i].devnode[0] ? devices[i].devnode : "N/A");
        
        strncat(buffer, device_str, buffer_size - strlen(buffer) - 1);
    }
    
    // Add additional port information
    strncat(buffer, "\n--- Port Status ---\n", buffer_size - strlen(buffer) - 1);
    
    FILE *fp = popen("lsusb -t 2>/dev/null", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(buffer, line, buffer_size - strlen(buffer) - 1);
        }
        pclose(fp);
    } else {
        strncat(buffer, "(lsusb command not available)\n", buffer_size - strlen(buffer) - 1);
    }
    
    // Get USB controller info
    strncat(buffer, "\n--- USB Controllers ---\n", buffer_size - strlen(buffer) - 1);
    
    fp = popen("lspci -D -d ::0c03 2>/dev/null || lspci | grep -i usb 2>/dev/null || echo 'PCI USB controller info unavailable'", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(buffer, line, buffer_size - strlen(buffer) - 1);
        }
        pclose(fp);
    }
    
    usb_free_device_list(devices, count);
    return buffer;
}

char* usb_get_hub_info(void) {
    size_t buffer_size = 4096;
    char *buffer = malloc(buffer_size);
    if (!buffer) return NULL;
    
    strcpy(buffer, "USB Hub Information\n====================\n\n");
    
    // Read hub information from sysfs
    DIR *dir = opendir("/sys/bus/usb/devices");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            
            char path[512];
            snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/bDeviceClass", entry->d_name);
            
            FILE *fp = fopen(path, "r");
            if (fp) {
                char bclass[16];
                if (fgets(bclass, sizeof(bclass), fp)) {
                    if (strstr(bclass, "09")) {  // Hub class
                        char info[512];
                        snprintf(info, sizeof(info), "Hub: %s\n", entry->d_name);
                        strncat(buffer, info, buffer_size - strlen(buffer) - 1);
                        
                        // Get number of ports
                        char portpath[512];
                        snprintf(portpath, sizeof(portpath), "/sys/bus/usb/devices/%s/bNumConfigurations", entry->d_name);
                        FILE *pfp = fopen(portpath, "r");
                        if (pfp) {
                            char ports[16];
                            if (fgets(ports, sizeof(ports), pfp)) {
                                snprintf(info, sizeof(info), "  Configurations: %s", ports);
                                strncat(buffer, info, buffer_size - strlen(buffer) - 1);
                            }
                            fclose(pfp);
                        }
                    }
                }
                fclose(fp);
            }
        }
        closedir(dir);
    }
    
    return buffer;
}

char* usb_get_detailed_port_info(void) {
    size_t buffer_size = 8192;
    char *buffer = malloc(buffer_size);
    if (!buffer) return NULL;
    
    strcpy(buffer, "USB Port Details\n=================\n\n");
    
    // Read from /sys/kernel/debug/usb/devices if available
    FILE *fp = fopen("/sys/kernel/debug/usb/devices", "r");
    if (fp) {
        strncat(buffer, "--- Kernel USB Debug Info ---\n", buffer_size - strlen(buffer) - 1);
        char line[256];
        while (fgets(line, sizeof(line), fp) && strlen(buffer) < buffer_size - 256) {
            strncat(buffer, line, buffer_size - strlen(buffer) - 1);
        }
        fclose(fp);
    } else {
        strncat(buffer, "Kernel debug info requires root access\n", buffer_size - strlen(buffer) - 1);
    }
    
    return buffer;
}

char* usb_get_device_tree(void) {
    size_t buffer_size = 8192;
    char *buffer = malloc(buffer_size);
    if (!buffer) return NULL;
    
    strcpy(buffer, "USB Device Tree\n================\n\n");
    
    FILE *fp = popen("lsusb -tv 2>/dev/null || lsusb -t 2>/dev/null || echo 'lsusb not available'", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) && strlen(buffer) < buffer_size - 256) {
            strncat(buffer, line, buffer_size - strlen(buffer) - 1);
        }
        pclose(fp);
    }
    
    return buffer;
}

char* usb_get_power_info(void) {
    size_t buffer_size = 4096;
    char *buffer = malloc(buffer_size);
    if (!buffer) return NULL;
    
    strcpy(buffer, "USB Power Information\n======================\n\n");
    
    // Check autosuspend settings
    strncat(buffer, "--- Power Management ---\n", buffer_size - strlen(buffer) - 1);
    
    FILE *fp = popen("find /sys/bus/usb/devices -name 'power' -type d 2>/dev/null | head -5 | while read p; do echo \"Device: $p\"; cat \"$p/control\" 2>/dev/null || echo 'N/A'; done", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(buffer, line, buffer_size - strlen(buffer) - 1);
        }
        pclose(fp);
    }
    
    return buffer;
}

char* usb_get_bandwidth_info(void) {
    size_t buffer_size = 4096;
    char *buffer = malloc(buffer_size);
    if (!buffer) return NULL;
    
    strcpy(buffer, "USB Bandwidth Usage\n====================\n\n");
    
    // Read bandwidth from debugfs if available
    FILE *fp = fopen("/sys/kernel/debug/usb/devices", "r");
    if (fp) {
        char line[256];
        int in_config = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (line[0] == 'T') {  // Topology
                in_config = 1;
            }
            if (in_config && (line[0] == 'I' || line[0] == 'E')) {  // Interface/Endpoint
                strncat(buffer, line, buffer_size - strlen(buffer) - 1);
            }
            if (line[0] == '\n') {
                in_config = 0;
            }
        }
        fclose(fp);
    }
    
    return buffer;
}
