#ifndef UI_H
#define UI_H

#include <ncurses.h>

// определения окон
#define WIN_MENU_WIDTH 30
#define WIN_STATUS_HEIGHT 3
#define MIN_COLS 80
#define MIN_LINES 24

// пункты меню
typedef enum {
    MENU_USB_DEVICES = 0,
    MENU_PCI_DEVICES,
    MENU_NETWORK_SCAN,
    MENU_NEARBY_DEVICES,
    MENU_BLUETOOTH,
    MENU_HARDWARE_INFO,
    MENU_SYSTEM_INFO,
    MENU_NETWORK_PROTOCOLS,
    MENU_DATA_ANALYSIS,
    MENU_HELP,
    MENU_EXIT,
    MENU_COUNT
} MenuItem;

// функции интерфейса
int ui_init(void);
void ui_cleanup(void);
void ui_main_loop(void);

// управление окнами
void draw_border(WINDOW *win, const char *title);
void draw_menu(void);
void draw_content(void);
void draw_status(void);
void update_content(const char *text);

// прокрутка
void scroll_content_up(int lines);
void scroll_content_down(int lines);
void scroll_content_top(void);
void scroll_content_bottom(void);

// обработка событий
void handle_input(int ch);
void refresh_all(void);

// отображение контента
void show_usb_devices(void);
void show_pci_devices(void);
void show_network_scan(void);
void show_bluetooth_devices(void);
void show_nearby_devices(void);
void show_hardware_info(void);
void show_system_info(void);
void show_network_protocols(void);
void show_data_analysis(void);
void show_help(void);

#endif // ui_h
