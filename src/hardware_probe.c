/*
 * модуль глубокого зондирования железа
 * доступ к расширенной информации через /sys и /proc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include "hardware_probe.h"

/* чтение строки из файла */
static int read_line(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    
    if (n < 0) return -1;
    
    buf[n] = '\0';
    
    /* удаляем перенос строки */
    char *p = strchr(buf, '\n');
    if (p) *p = '\0';
    
    return 0;
}

/* чтение целого числа */
static long read_long(const char *path) {
    char buf[64];
    if (read_line(path, buf, sizeof(buf)) != 0) {
        return -1;
    }
    return strtol(buf, NULL, 10);
}

/* парсинг cpuinfo */
int probe_cpu_info(cpu_info_t *info) {
    FILE *f;
    char buf[256];
    int cpu_count = 0;
    int found_model = 0;
    
    memset(info, 0, sizeof(*info));
    
    f = fopen("/proc/cpuinfo", "r");
    if (!f) return -1;
    
    while (fgets(buf, sizeof(buf), f)) {
        /* подсчет процессоров */
        if (strncmp(buf, "processor", 9) == 0) {
            cpu_count++;
        }
        /* модель */
        else if (!found_model && strncmp(buf, "model name", 10) == 0) {
            char *p = strchr(buf, ':');
            if (p) {
                p++;
                while (*p == ' ' || *p == '\t') p++;
                strncpy(info->model_name, p, sizeof(info->model_name) - 1);
                info->model_name[sizeof(info->model_name) - 1] = '\0';
                
                /* удаляем перенос */
                char *nl = strchr(info->model_name, '\n');
                if (nl) *nl = '\0';
                found_model = 1;
            }
        }
        /* архитектура */
        else if (strncmp(buf, "Architecture", 12) == 0) {
            char *p = strchr(buf, ':');
            if (p) {
                p++;
                while (*p == ' ' || *p == '\t') p++;
                strncpy(info->architecture, p, sizeof(info->architecture) - 1);
                info->architecture[sizeof(info->architecture) - 1] = '\0';
                char *nl = strchr(info->architecture, '\n');
                if (nl) *nl = '\0';
            }
        }
        /* cpu cores */
        else if (strncmp(buf, "cpu cores", 9) == 0) {
            char *p = strchr(buf, ':');
            if (p) {
                info->cores_per_socket = atoi(p + 1);
            }
        }
        /* siblings - потоков на сокет */
        else if (strncmp(buf, "siblings", 8) == 0) {
            char *p = strchr(buf, ':');
            if (p) {
                info->threads_per_socket = atoi(p + 1);
            }
        }
        /* частота */
        else if (strncmp(buf, "cpu MHz", 7) == 0) {
            if (info->cpu_mhz == 0) { /* берем первую */
                char *p = strchr(buf, ':');
                if (p) {
                    info->cpu_mhz = (int)strtol(p + 1, NULL, 10);
                }
            }
        }
        /* cache size */
        else if (strncmp(buf, "cache size", 10) == 0) {
            char *p = strchr(buf, ':');
            if (p) {
                info->cache_size_kb = atoi(p + 1);
            }
        }
        /* bogomips */
        else if (strncmp(buf, "bogomips", 8) == 0) {
            if (info->bogomips == 0) {
                char *p = strchr(buf, ':');
                if (p) {
                    info->bogomips = strtod(p + 1, NULL);
                }
            }
        }
        /* flags - для определения возможностей */
        else if (strncmp(buf, "flags", 5) == 0) {
            /* проверяем наличие vmx/svm (виртуализация) */
            if (strstr(buf, "vmx") || strstr(buf, "svm")) {
                info->has_virtualization = 1;
            }
            /* проверяем aes */
            if (strstr(buf, "aes")) {
                info->has_aes = 1;
            }
            /* проверяем avx/avx2 */
            if (strstr(buf, "avx2")) {
                info->has_avx2 = 1;
            } else if (strstr(buf, "avx")) {
                info->has_avx = 1;
            }
        }
        /* vendor id */
        else if (strncmp(buf, "vendor_id", 9) == 0) {
            char *p = strchr(buf, ':');
            if (p) {
                p++;
                while (*p == ' ' || *p == '\t') p++;
                strncpy(info->vendor, p, sizeof(info->vendor) - 1);
                info->vendor[sizeof(info->vendor) - 1] = '\0';
                char *nl = strchr(info->vendor, '\n');
                if (nl) *nl = '\0';
            }
        }
        /* physical id - для подсчета сокетов */
        else if (strncmp(buf, "physical id", 11) == 0) {
            char *p = strchr(buf, ':');
            if (p) {
                int id = atoi(p + 1);
                if (id >= info->num_sockets) {
                    info->num_sockets = id + 1;
                }
            }
        }
    }
    
    fclose(f);
    
    info->num_cores = cpu_count;
    if (info->num_sockets == 0) info->num_sockets = 1;
    
    return 0;
}

/* получение информации о памяти */
int probe_memory_info(memory_info_t *info) {
    FILE *f;
    char buf[256];
    
    memset(info, 0, sizeof(*info));
    
    f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    
    while (fgets(buf, sizeof(buf), f)) {
        unsigned long val;
        char *p;
        
        if (strncmp(buf, "MemTotal:", 9) == 0) {
            sscanf(buf, "MemTotal: %lu", &val);
            info->total_kb = val;
        }
        else if (strncmp(buf, "MemFree:", 8) == 0) {
            sscanf(buf, "MemFree: %lu", &val);
            info->free_kb = val;
        }
        else if (strncmp(buf, "MemAvailable:", 13) == 0) {
            sscanf(buf, "MemAvailable: %lu", &val);
            info->available_kb = val;
        }
        else if (strncmp(buf, "Buffers:", 8) == 0) {
            sscanf(buf, "Buffers: %lu", &val);
            info->buffers_kb = val;
        }
        else if (strncmp(buf, "Cached:", 7) == 0) {
            sscanf(buf, "Cached: %lu", &val);
            info->cached_kb = val;
        }
        else if (strncmp(buf, "SwapTotal:", 10) == 0) {
            sscanf(buf, "SwapTotal: %lu", &val);
            info->swap_total_kb = val;
        }
        else if (strncmp(buf, "SwapFree:", 9) == 0) {
            sscanf(buf, "SwapFree: %lu", &val);
            info->swap_free_kb = val;
        }
        else if (strncmp(buf, "HugePages_Total:", 16) == 0) {
            sscanf(buf, "HugePages_Total: %lu", &val);
            info->hugepages_total = val;
        }
    }
    
    fclose(f);
    
    info->used_kb = info->total_kb - info->available_kb;
    if (info->total_kb > 0) {
        info->usage_percent = (info->used_kb * 100) / info->total_kb;
    }
    
    return 0;
}

/* получение температур */
int probe_temperatures(temp_info_t **temps, int *count) {
    DIR *dir;
    struct dirent *entry;
    temp_info_t *list = NULL;
    int n = 0;
    int capacity = 16;
    
    *temps = NULL;
    *count = 0;
    
    /* проверяем thermal zones */
    dir = opendir("/sys/class/thermal");
    if (!dir) return -1;
    
    list = malloc(capacity * sizeof(temp_info_t));
    if (!list) {
        closedir(dir);
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        char path[256];
        long temp;
        
        if (strncmp(entry->d_name, "thermal_zone", 12) != 0) {
            continue;
        }
        
        /* читаем температуру */
        snprintf(path, sizeof(path), "/sys/class/thermal/%s/temp", entry->d_name);
        temp = read_long(path);
        if (temp < 0) continue;
        
        /* расширяем массив если нужно */
        if (n >= capacity) {
            capacity *= 2;
            temp_info_t *new_list = realloc(list, capacity * sizeof(temp_info_t));
            if (!new_list) break;
            list = new_list;
        }
        
        /* читаем тип */
        char type[64] = "unknown";
        snprintf(path, sizeof(path), "/sys/class/thermal/%s/type", entry->d_name);
        read_line(path, type, sizeof(type));
        
        /* заполняем структуру */
        strncpy(list[n].name, entry->d_name, sizeof(list[n].name) - 1);
        list[n].name[sizeof(list[n].name) - 1] = '\0';
        strncpy(list[n].type, type, sizeof(list[n].type) - 1);
        list[n].type[sizeof(list[n].type) - 1] = '\0';
        list[n].temp_millicelsius = temp;
        list[n].temp_celsius = temp / 1000;
        
        n++;
    }
    
    closedir(dir);
    
    /* проверяем hwmon */
    dir = opendir("/sys/class/hwmon");
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            char hwmon_path[256];
            DIR *hwmon_dir;
            struct dirent *hwmon_entry;
            char name[64] = "unknown";
            
            if (strncmp(entry->d_name, "hwmon", 5) != 0) continue;
            
            snprintf(hwmon_path, sizeof(hwmon_path), "/sys/class/hwmon/%s", entry->d_name);
            
            /* читаем имя чипа */
            snprintf(hwmon_path, sizeof(hwmon_path), "/sys/class/hwmon/%s/name", entry->d_name);
            read_line(hwmon_path, name, sizeof(name));
            
            /* ищем температурные входы */
            snprintf(hwmon_path, sizeof(hwmon_path), "/sys/class/hwmon/%s", entry->d_name);
            hwmon_dir = opendir(hwmon_path);
            if (!hwmon_dir) continue;
            
            while ((hwmon_entry = readdir(hwmon_dir)) != NULL) {
                if (strstr(hwmon_entry->d_name, "temp") && strstr(hwmon_entry->d_name, "_input")) {
                    char temp_path[256];
                    long temp;
                    char label[64] = "";
                    
                    snprintf(temp_path, sizeof(temp_path), "%s/%s", hwmon_path, hwmon_entry->d_name);
                    temp = read_long(temp_path);
                    if (temp < 0) continue;
                    
                    /* читаем метку */
                    char label_name[64];
                    strncpy(label_name, hwmon_entry->d_name, sizeof(label_name) - 1);
                    label_name[strlen(label_name) - 6] = '\0'; /* убираем _input */
                    strcat(label_name, "_label");
                    snprintf(temp_path, sizeof(temp_path), "%s/%s", hwmon_path, label_name);
                    read_line(temp_path, label, sizeof(label));
                    
                    if (n >= capacity) {
                        capacity *= 2;
                        temp_info_t *new_list = realloc(list, capacity * sizeof(temp_info_t));
                        if (!new_list) break;
                        list = new_list;
                    }
                    
                    snprintf(list[n].name, sizeof(list[n].name), "%s/%s", entry->d_name, hwmon_entry->d_name);
                    if (strlen(label) > 0) {
                        snprintf(list[n].type, sizeof(list[n].type), "%s - %s", name, label);
                    } else {
                        strncpy(list[n].type, name, sizeof(list[n].type) - 1);
                    }
                    list[n].type[sizeof(list[n].type) - 1] = '\0';
                    list[n].temp_millicelsius = temp;
                    list[n].temp_celsius = temp / 1000;
                    
                    n++;
                }
            }
            
            closedir(hwmon_dir);
        }
        closedir(dir);
    }
    
    *temps = list;
    *count = n;
    return 0;
}

/* информация о дисках */
int probe_disk_info(disk_info_t **disks, int *count) {
    FILE *f;
    char buf[256];
    disk_info_t *list = NULL;
    int n = 0;
    int capacity = 16;
    
    *disks = NULL;
    *count = 0;
    
    f = fopen("/proc/mounts", "r");
    if (!f) return -1;
    
    list = malloc(capacity * sizeof(disk_info_t));
    if (!list) {
        fclose(f);
        return -1;
    }
    
    while (fgets(buf, sizeof(buf), f)) {
        char device[128], mountpoint[128], fstype[32];
        struct statvfs vfs;
        
        if (sscanf(buf, "%127s %127s %31s", device, mountpoint, fstype) != 3) {
            continue;
        }
        
        /* пропускаем виртуальные ФС */
        if (strncmp(device, "/dev/", 5) != 0) continue;
        if (strstr(device, "loop")) continue;
        if (strcmp(fstype, "tmpfs") == 0 || strcmp(fstype, "devtmpfs") == 0) continue;
        if (strcmp(fstype, "cgroup") == 0 || strcmp(fstype, "proc") == 0) continue;
        if (strcmp(fstype, "sysfs") == 0 || strcmp(fstype, "devpts") == 0) continue;
        
        /* статистика */
        if (statvfs(mountpoint, &vfs) != 0) continue;
        
        if (n >= capacity) {
            capacity *= 2;
            disk_info_t *new_list = realloc(list, capacity * sizeof(disk_info_t));
            if (!new_list) break;
            list = new_list;
        }
        
        strncpy(list[n].device, device, sizeof(list[n].device) - 1);
        list[n].device[sizeof(list[n].device) - 1] = '\0';
        strncpy(list[n].mountpoint, mountpoint, sizeof(list[n].mountpoint) - 1);
        list[n].mountpoint[sizeof(list[n].mountpoint) - 1] = '\0';
        strncpy(list[n].filesystem, fstype, sizeof(list[n].filesystem) - 1);
        list[n].filesystem[sizeof(list[n].filesystem) - 1] = '\0';
        
        unsigned long long total = vfs.f_blocks * vfs.f_frsize;
        unsigned long long free = vfs.f_bavail * vfs.f_frsize;
        unsigned long long used = total - free;
        
        list[n].total_bytes = total;
        list[n].used_bytes = used;
        list[n].free_bytes = free;
        
        if (total > 0) {
            list[n].usage_percent = (int)((used * 100) / total);
        } else {
            list[n].usage_percent = 0;
        }
        
        n++;
    }
    
    fclose(f);
    
    *disks = list;
    *count = n;
    return 0;
}

/* информация о сетевых интерфейсах */
int probe_network_interfaces(net_iface_t **ifaces, int *count) {
    FILE *f;
    char buf[512];
    net_iface_t *list = NULL;
    int n = 0;
    int capacity = 16;
    
    *ifaces = NULL;
    *count = 0;
    
    f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    
    list = malloc(capacity * sizeof(net_iface_t));
    if (!list) {
        fclose(f);
        return -1;
    }
    
    /* пропускаем 2 заголовка */
    fgets(buf, sizeof(buf), f);
    fgets(buf, sizeof(buf), f);
    
    while (fgets(buf, sizeof(buf), f)) {
        char *p = buf;
        char name[32];
        unsigned long long rx_bytes, rx_packets, rx_errs, rx_drop;
        unsigned long long tx_bytes, tx_packets, tx_errs, tx_drop;
        unsigned long long rx_fifo, rx_frame, rx_compressed, rx_multicast;
        unsigned long long tx_fifo, tx_colls, tx_carrier, tx_compressed;
        
        /* формат: iface: rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast tx_bytes tx_packets tx_errs tx_drop tx_fifo tx_colls tx_carrier tx_compressed */
        
        /* пропускаем пробелы */
        while (*p == ' ') p++;
        
        /* имя интерфейса */
        char *name_end = strchr(p, ':');
        if (!name_end) continue;
        
        *name_end = '\0';
        strncpy(name, p, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
        p = name_end + 1;
        
        /* пропускаем loopback */
        if (strcmp(name, "lo") == 0) continue;
        
        /* парсим значения */
        if (sscanf(p, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &rx_bytes, &rx_packets, &rx_errs, &rx_drop,
                   &rx_fifo, &rx_frame, &rx_compressed, &rx_multicast,
                   &tx_bytes, &tx_packets, &tx_errs, &tx_drop,
                   &tx_fifo, &tx_colls, &tx_carrier, &tx_compressed) != 16) {
            continue;
        }
        
        if (n >= capacity) {
            capacity *= 2;
            net_iface_t *new_list = realloc(list, capacity * sizeof(net_iface_t));
            if (!new_list) break;
            list = new_list;
        }
        
        strncpy(list[n].name, name, sizeof(list[n].name) - 1);
        list[n].name[sizeof(list[n].name) - 1] = '\0';
        list[n].rx_bytes = rx_bytes;
        list[n].rx_packets = rx_packets;
        list[n].rx_errors = rx_errs;
        list[n].rx_dropped = rx_drop;
        list[n].tx_bytes = tx_bytes;
        list[n].tx_packets = tx_packets;
        list[n].tx_errors = tx_errs;
        list[n].tx_dropped = tx_drop;
        
        /* определяем тип интерфейса */
        if (strncmp(name, "wl", 2) == 0 || strncmp(name, "wlan", 4) == 0 || strncmp(name, "wlp", 3) == 0) {
            list[n].is_wireless = 1;
        } else if (strncmp(name, "eth", 3) == 0 || strncmp(name, "en", 2) == 0 || strncmp(name, "eno", 3) == 0) {
            list[n].is_wireless = 0;
        } else {
            list[n].is_wireless = -1; /* unknown */
        }
        
        /* пытаемся получить MAC и IP */
        char operstate_path[256];
        char operstate[16] = "unknown";
        snprintf(operstate_path, sizeof(operstate_path), "/sys/class/net/%s/operstate", name);
        read_line(operstate_path, operstate, sizeof(operstate));
        strncpy(list[n].status, operstate, sizeof(list[n].status) - 1);
        list[n].status[sizeof(list[n].status) - 1] = '\0';
        
        /* MAC адрес */
        char mac_path[256];
        snprintf(mac_path, sizeof(mac_path), "/sys/class/net/%s/address", name);
        if (read_line(mac_path, list[n].mac, sizeof(list[n].mac)) != 0) {
            strcpy(list[n].mac, "unknown");
        }
        
        n++;
    }
    
    fclose(f);
    
    *ifaces = list;
    *count = n;
    return 0;
}

/* информация о батарее */
int probe_battery_info(battery_info_t *info) {
    DIR *dir;
    struct dirent *entry;
    char path[256];
    
    memset(info, 0, sizeof(*info));
    info->present = 0;
    
    dir = opendir("/sys/class/power_supply");
    if (!dir) return -1;
    
    while ((entry = readdir(dir)) != NULL) {
        char type[32];
        
        if (strncmp(entry->d_name, "BAT", 3) != 0) continue;
        
        /* проверяем тип */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/type", entry->d_name);
        if (read_line(path, type, sizeof(type)) != 0) continue;
        if (strcmp(type, "Battery") != 0) continue;
        
        info->present = 1;
        strncpy(info->name, entry->d_name, sizeof(info->name) - 1);
        info->name[sizeof(info->name) - 1] = '\0';
        
        /* статус */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/status", entry->d_name);
        read_line(path, info->status, sizeof(info->status));
        
        /* емкость */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/capacity", entry->d_name);
        long cap = read_long(path);
        if (cap >= 0) info->capacity_percent = (int)cap;
        
        /* здоровье */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/health", entry->d_name);
        if (read_line(path, info->health, sizeof(info->health)) != 0) {
            strcpy(info->health, "unknown");
        }
        
        /* технология */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/technology", entry->d_name);
        read_line(path, info->technology, sizeof(info->technology));
        
        /* напряжение */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/voltage_now", entry->d_name);
        long volt = read_long(path);
        if (volt > 0) info->voltage_now_uv = volt;
        
        /* текущий заряд */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/charge_now", entry->d_name);
        long charge = read_long(path);
        if (charge > 0) {
            info->charge_now_mah = charge / 1000; /* обычно в uAh */
        }
        
        /* полная емкость */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/charge_full", entry->d_name);
        long full = read_long(path);
        if (full > 0) {
            info->charge_full_mah = full / 1000;
        }
        
        /* дизайн емкость */
        snprintf(path, sizeof(path), "/sys/class/power_supply/%s/charge_full_design", entry->d_name);
        long design = read_long(path);
        if (design > 0) {
            info->charge_design_mah = design / 1000;
            /* вычисляем износ */
            if (info->charge_full_mah > 0) {
                info->cycle_count = 0; /* обычно недоступно */
            }
        }
        
        break; /* берем первую батарею */
    }
    
    closedir(dir);
    return info->present ? 0 : -1;
}

/* освобождение памяти */
void probe_free_temperatures(temp_info_t *temps) {
    free(temps);
}

void probe_free_disks(disk_info_t *disks) {
    free(disks);
}

void probe_free_interfaces(net_iface_t *ifaces) {
    free(ifaces);
}
