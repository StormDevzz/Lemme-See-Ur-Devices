/*
 * заголовок модуля глубокого зондирования железа
 */

#ifndef HARDWARE_PROBE_H
#define HARDWARE_PROBE_H

#include <sys/types.h>
#include <sys/statvfs.h>
#include <stdint.h>
#include <time.h>

/* информация о процессоре */
typedef struct {
    char model_name[128];
    char vendor[32];
    char architecture[32];
    int num_cores;
    int num_sockets;
    int cores_per_socket;
    int threads_per_socket;
    int cpu_mhz;
    int cache_size_kb;
    double bogomips;
    
    /* флаги возможностей */
    int has_virtualization;
    int has_aes;
    int has_avx;
    int has_avx2;
} cpu_info_t;

/* информация о памяти */
typedef struct {
    unsigned long total_kb;
    unsigned long free_kb;
    unsigned long available_kb;
    unsigned long used_kb;
    unsigned long buffers_kb;
    unsigned long cached_kb;
    unsigned long swap_total_kb;
    unsigned long swap_free_kb;
    unsigned long swap_used_kb;
    unsigned long hugepages_total;
    int usage_percent;
} memory_info_t;

/* температурный датчик */
typedef struct {
    char name[64];
    char type[64];
    long temp_millicelsius;
    int temp_celsius;
} temp_info_t;

/* информация о диске */
typedef struct {
    char device[128];
    char mountpoint[256];
    char filesystem[32];
    unsigned long long total_bytes;
    unsigned long long used_bytes;
    unsigned long long free_bytes;
    int usage_percent;
} disk_info_t;

/* сетевой интерфейс */
typedef struct {
    char name[32];
    char mac[32];
    char status[16];  /* up/down/unknown */
    int is_wireless;  /* -1 = unknown, 0 = no, 1 = yes */
    unsigned long long rx_bytes;
    unsigned long long rx_packets;
    unsigned long long rx_errors;
    unsigned long long rx_dropped;
    unsigned long long tx_bytes;
    unsigned long long tx_packets;
    unsigned long long tx_errors;
    unsigned long long tx_dropped;
} net_iface_t;

/* информация о батарее */
typedef struct {
    int present;
    char name[32];
    char status[32];      /* charging/discharging/full/unknown */
    char health[32];      /* good/overheat/dead/unknown */
    char technology[32];/* li-ion/li-polymer/etc */
    int capacity_percent;
    int charge_now_mah;
    int charge_full_mah;
    int charge_design_mah;
    int cycle_count;
    long voltage_now_uv;
} battery_info_t;

/* функции */

/* парсинг cpuinfo */
int probe_cpu_info(cpu_info_t *info);

/* информация о памяти */
int probe_memory_info(memory_info_t *info);

/* получение температур (массив) */
int probe_temperatures(temp_info_t **temps, int *count);

/* информация о дисках */
int probe_disk_info(disk_info_t **disks, int *count);

/* информация о сетевых интерфейсах */
int probe_network_interfaces(net_iface_t **ifaces, int *count);

/* информация о батарее */
int probe_battery_info(battery_info_t *info);

/* освобождение памяти */
void probe_free_temperatures(temp_info_t *temps);
void probe_free_disks(disk_info_t *disks);
void probe_free_interfaces(net_iface_t *ifaces);

#endif /* HARDWARE_PROBE_H */
