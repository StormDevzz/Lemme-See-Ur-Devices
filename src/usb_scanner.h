#ifndef USB_SCANNER_H
#define USB_SCANNER_H

#include <libudev.h>

// структура информации об usb устройстве
typedef struct {
    char vendor[256];
    char model[256];
    char serial[256];
    char devnode[256];
    char sysname[256];
    char id_vendor[32];
    char id_product[32];
    char busnum[16];
    char devnum[16];
    char manufacturer[256];
    char product[256];
    unsigned int speed;
} usb_device_info_t;

// информация о usb хабе/порте
typedef struct {
    char hub_path[256];
    int port_count;
    int ports_occupied;
    char power_status[64];
} usb_hub_info_t;

// функции
int usb_scanner_init(void);
void usb_scanner_cleanup(void);

char* usb_get_device_list(void);
char* usb_get_hub_info(void);
char* usb_get_detailed_port_info(void);

int usb_enumerate_devices(usb_device_info_t **devices, int *count);
void usb_free_device_list(usb_device_info_t *devices, int count);

// глубокая инспекция
char* usb_get_device_tree(void);
char* usb_get_power_info(void);
char* usb_get_bandwidth_info(void);

#endif // usb_scanner_h
