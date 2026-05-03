/*
 * модуль интерфейса - оконное меню с использованием ncurses
 */

#include "ui.h"
#include "usb_scanner.h"
#include "hardware_info.h"
#include "lua_bridge.h"
#include "python_bridge.h"
#include <string.h>
#include <stdlib.h>

static WINDOW *win_menu = NULL;
static WINDOW *win_content = NULL;
static WINDOW *win_status = NULL;

static int selected_item = 0;
static int content_scroll = 0;
static int total_lines = 0;
static char content_buffer[32768] = {0};
static char **content_lines = NULL;
static int content_line_count = 0;

static const char *menu_items[MENU_COUNT] = {
    "USB Devices",
    "PCI Devices", 
    "Network Scan",
    "Nearby Devices",
    "Bluetooth",
    "Hardware Info",
    "System Info",
    "Network Protocols",
    "Data Analysis",
    "Help",
    "Exit"
};

static const char *menu_descriptions[MENU_COUNT] = {
    "Scan and analyze USB connected devices with serial numbers",
    "List PCI/PCIe devices on the system",
    "Discover devices on local network",
    "Detect phones, IoT devices, and gadgets nearby",
    "Bluetooth device discovery and analysis",
    "Deep hardware inspection (ASM enhanced)",
    "System information and resources",
    "Network protocol analysis (Lua powered)",
    "Advanced data analysis (Python powered)",
    "Show help and usage information",
    "Exit the application"
};

int ui_init(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    
    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_WHITE, COLOR_BLUE);
        init_pair(2, COLOR_BLACK, COLOR_WHITE);
        init_pair(3, COLOR_GREEN, COLOR_BLACK);
        init_pair(4, COLOR_YELLOW, COLOR_BLACK);
        init_pair(5, COLOR_RED, COLOR_BLACK);
        init_pair(6, COLOR_CYAN, COLOR_BLACK);
    }
    
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    
    // минимальный разумный размер, но позволяем меньшие терминалы
    int menu_width = (cols > 40) ? WIN_MENU_WIDTH : cols / 3;
    if (menu_width < 15) menu_width = 15;
    
    int status_height = (rows > 5) ? WIN_STATUS_HEIGHT : 1;
    
    // создание окон с динамическим размером
    win_menu = newwin(rows - status_height, menu_width, 0, 0);
    win_content = newwin(rows - status_height, cols - menu_width, 0, menu_width);
    win_status = newwin(status_height, cols, rows - status_height, 0);
    
    if (!win_menu || !win_content || !win_status) {
        ui_cleanup();
        return -1;
    }
    
    scrollok(win_content, TRUE);
    
    strcpy(content_buffer, "Welcome to Device Analyzer\n\nSelect an option from the menu.\n\nThis tool combines:\n- C for system interface\n- Assembly for deep hardware inspection\n- Lua for network protocols\n- Python for data analysis");
    
    return 0;
}

void ui_cleanup(void) {
    if (win_menu) delwin(win_menu);
    if (win_content) delwin(win_content);
    if (win_status) delwin(win_status);
    endwin();
}

void draw_border(WINDOW *win, const char *title) {
    box(win, 0, 0);
    if (title) {
        mvwprintw(win, 0, 2, " %s ", title);
    }
    wrefresh(win);
}

void draw_menu(void) {
    werase(win_menu);
    
    if (has_colors()) {
        wbkgd(win_menu, COLOR_PAIR(1));
    }
    
    draw_border(win_menu, "MENU");
    
    for (int i = 0; i < MENU_COUNT; i++) {
        int y = 2 + i;
        if (y >= getmaxy(win_menu) - 1) break;
        
        if (i == selected_item) {
            if (has_colors()) {
                wattron(win_menu, COLOR_PAIR(2) | A_BOLD);
            } else {
                wattron(win_menu, A_REVERSE);
            }
            mvwprintw(win_menu, y, 2, " > %s", menu_items[i]);
            if (has_colors()) {
                wattroff(win_menu, COLOR_PAIR(2) | A_BOLD);
            } else {
                wattroff(win_menu, A_REVERSE);
            }
        } else {
            mvwprintw(win_menu, y, 2, "   %s", menu_items[i]);
        }
    }
    
    wrefresh(win_menu);
}

static void rebuild_content_lines(void) {
    // освобождаем старые строки
    if (content_lines) {
        for (int i = 0; i < content_line_count; i++) {
            free(content_lines[i]);
        }
        free(content_lines);
    }
    
    // подсчет строк
    content_line_count = 0;
    char *tmp = strdup(content_buffer);
    char *p = tmp;
    while (*p) {
        if (*p == '\n') content_line_count++;
        p++;
    }
    if (content_buffer[0] && p[-1] != '\n') content_line_count++;
    
    // выделение памяти и заполнение
    content_lines = malloc(sizeof(char*) * (content_line_count + 1));
    p = content_buffer;
    int idx = 0;
    char line_buf[1024];
    int pos = 0;
    
    while (*p) {
        if (*p == '\n' || pos >= sizeof(line_buf) - 1) {
            line_buf[pos] = '\0';
            content_lines[idx++] = strdup(line_buf);
            pos = 0;
        } else {
            line_buf[pos++] = *p;
        }
        p++;
    }
    if (pos > 0) {
        line_buf[pos] = '\0';
        content_lines[idx++] = strdup(line_buf);
    }
    content_line_count = idx;
    free(tmp);
}

void draw_content(void) {
    werase(win_content);
    draw_border(win_content, "CONTENT");
    
    int max_y = getmaxy(win_content) - 2;
    int max_lines = max_y - 2;
    
    // проверка границ прокрутки
    if (content_scroll < 0) content_scroll = 0;
    if (content_scroll > content_line_count - max_lines) {
        content_scroll = content_line_count - max_lines;
        if (content_scroll < 0) content_scroll = 0;
    }
    
    // отрисовка видимых строк
    for (int i = 0; i < max_lines && (content_scroll + i) < content_line_count; i++) {
        mvwprintw(win_content, 2 + i, 2, "%.*s", getmaxx(win_content) - 4, 
                  content_lines[content_scroll + i]);
    }
    
    // индикатор прокрутки при необходимости
    if (content_line_count > max_lines) {
        int scroll_pct = (content_scroll * 100) / (content_line_count - max_lines);
        mvwprintw(win_content, max_y - 1, getmaxx(win_content) - 8, "[%2d%%]", scroll_pct);
    }
    
    wrefresh(win_content);
}

void scroll_content_up(int lines) {
    content_scroll -= lines;
    if (content_scroll < 0) content_scroll = 0;
    draw_content();
}

void scroll_content_down(int lines) {
    content_scroll += lines;
    draw_content();
}

void scroll_content_top(void) {
    content_scroll = 0;
    draw_content();
}

void scroll_content_bottom(void) {
    content_scroll = content_line_count;
    draw_content();
}

void draw_status(void) {
    werase(win_status);
    
    if (has_colors()) {
        wbkgd(win_status, COLOR_PAIR(3));
    }
    
    draw_border(win_status, NULL);
    
    mvwprintw(win_status, 1, 2, "[↑↓:Menu] [PgUp/PgDn:Scroll] [Enter:Select] [Q:Quit] | %s", 
              menu_descriptions[selected_item]);
    
    wrefresh(win_status);
}

void update_content(const char *text) {
    if (strlen(text) >= sizeof(content_buffer)) {
        strncpy(content_buffer, text, sizeof(content_buffer) - 1);
        content_buffer[sizeof(content_buffer) - 1] = '\0';
    } else {
        strcpy(content_buffer, text);
    }
    content_scroll = 0;
    rebuild_content_lines();
    draw_content();
}

void show_usb_devices(void) {
    char *info = usb_get_device_list();
    if (info) {
        update_content(info);
        free(info);
    } else {
        update_content("Error scanning USB devices\n\nEnsure you have permissions:\n- Run as root, or\n- Add user to 'plugdev' group");
    }
}

void show_pci_devices(void) {
    FILE *fp = popen("lspci -nn 2>/dev/null || echo 'lspci not available - install pciutils'", "r");
    if (fp) {
        char buffer[4096] = {0};
        char line[256];
        strcat(buffer, "PCI/PCIe Devices:\n\n");
        while (fgets(line, sizeof(line), fp)) {
            strncat(buffer, line, sizeof(buffer) - strlen(buffer) - 1);
        }
        pclose(fp);
        update_content(buffer);
    }
}

void show_network_scan(void) {
    update_content("Network Scan - Initiating Lua discovery...\n");
    char *result = lua_network_scan();
    if (result) {
        update_content(result);
        free(result);
    } else {
        update_content("Network scan failed.\n\nEnsure Lua bridge is properly initialized.");
    }
}

void show_bluetooth_devices(void) {
    update_content("Bluetooth Device Discovery\n==========================\n\nScanning for Bluetooth devices...\n");
    char *result = lua_bluetooth_scan();
    if (result) {
        update_content(result);
        free(result);
    } else {
        update_content("Bluetooth scan failed.\n\nEnsure bluetoothctl or hcitool is available.");
    }
}

void show_nearby_devices(void) {
    update_content("Nearby Device Discovery (Phones, IoT, Gadgets)\n============================================\n\nDetecting nearby devices via mDNS, UPnP, and ARP...\n");
    char *result = lua_nearby_devices_scan();
    if (result) {
        update_content(result);
        free(result);
    } else {
        update_content("Nearby device scan failed.\n\nEnsure avahi-browse or gssdp-discover is available.");
    }
}

void show_hardware_info(void) {
    char buffer[4096] = {0};
    
    strcat(buffer, "Hardware Information (Assembly-enhanced)\n");
    strcat(buffer, "=========================================\n\n");
    
    // информация о процессоре из asm
    char *cpu_serial = hardware_get_cpu_serial();
    if (cpu_serial) {
        strcat(buffer, "CPU Serial/Info:\n");
        strcat(buffer, cpu_serial);
        strcat(buffer, "\n\n");
        free(cpu_serial);
    }
    
    // информация cpuid
    char *cpuid_info = hardware_get_cpuid_info();
    if (cpuid_info) {
        strcat(buffer, "CPUID Information:\n");
        strcat(buffer, cpuid_info);
        strcat(buffer, "\n\n");
        free(cpuid_info);
    }
    
    // глубокое сканирование железа (asm)
    char *deep_info = hardware_get_deep_scan_info();
    if (deep_info) {
        strcat(buffer, "Deep Hardware Scan:\n");
        strcat(buffer, deep_info);
        free(deep_info);
    }
    
    // информация dmi
    char *dmi_info = hardware_get_dmi_info();
    if (dmi_info) {
        strcat(buffer, "\n");
        strcat(buffer, dmi_info);
        free(dmi_info);
    }
    
    update_content(buffer);
}

void show_system_info(void) {
    char buffer[4096] = {0};
    
    strcat(buffer, "System Information:\n");
    strcat(buffer, "==================\n\n");
    
    FILE *fp = popen("uname -a", "r");
    if (fp) {
        char line[256];
        strcat(buffer, "Kernel: ");
        if (fgets(line, sizeof(line), fp)) {
            strcat(buffer, line);
        }
        pclose(fp);
    }
    
    fp = popen("cat /proc/cpuinfo | grep 'model name' | head -1", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            strcat(buffer, "CPU: ");
            strcat(buffer, strchr(line, ':') ? strchr(line, ':') + 2 : line);
            strcat(buffer, "\n");
        }
        pclose(fp);
    }
    
    fp = popen("cat /proc/meminfo | grep MemTotal", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            strcat(buffer, "Memory: ");
            strcat(buffer, strchr(line, ':') ? strchr(line, ':') + 2 : line);
            strcat(buffer, "\n");
        }
        pclose(fp);
    }
    
    update_content(buffer);
}

void show_network_protocols(void) {
    update_content("Network Protocols - Lua Analysis\n");
    char *result = lua_analyze_protocols();
    if (result) {
        update_content(result);
        free(result);
    }
}

void show_data_analysis(void) {
    update_content("Data Analysis - Python Integration\n");
    char *result = python_analyze_data();
    if (result) {
        update_content(result);
        free(result);
    }
}

void show_help(void) {
    const char *help_text = 
        "Device Analyzer - Help\n"
        "=======================\n\n"
        "Navigation:\n"
        "  ↑/↓ or k/j     - Navigate menu\n"
        "  Enter          - Select item\n"
        "  PgUp/PgDn      - Scroll content\n"
        "  Home/End       - Jump to top/bottom\n"
        "  Q              - Quit\n"
        "  F1             - This help\n\n"
        "Features:\n"
        "  USB Devices    - Serial numbers, vendor info, speed\n"
        "  PCI Devices    - PCI/PCIe enumeration\n"
        "  Network Scan   - Local network discovery\n"
        "  Nearby Devices - Phones, IoT, TVs via mDNS/UPnP\n"
        "  Bluetooth      - BT device discovery\n"
        "  Hardware Info  - CPUID, DMI, TPM (ASM enhanced)\n"
        "  System Info    - Kernel, CPU, memory\n"
        "  Network Proto  - Protocol analysis (Lua)\n"
        "  Data Analysis  - Python analytics & reports\n\n"
        "Architecture:\n"
        "  - C:      UI, USB scanning, system integration\n"
        "  - ASM:    CPUID, MSR, low-level hardware access\n"
        "  - Lua:    Network protocols, mDNS, UPnP, Bluetooth\n"
        "  - Python: Data analysis, vendor database, JSON export\n\n"
        "Requirements:\n"
        "  - libncursesw5-dev, libudev-dev\n"
        "  - liblua5.3-dev, python3-dev\n"
        "  - nasm, bluez (for Bluetooth), avahi (for mDNS)\n\n"
        "Permissions:\n"
        "  Some features need root for full hardware access";
    
    update_content(help_text);
}

void handle_input(int ch) {
    switch (ch) {
        case KEY_UP:
        case 'k':
            if (selected_item > 0) selected_item--;
            break;
            
        case KEY_DOWN:
        case 'j':
            if (selected_item < MENU_COUNT - 1) selected_item++;
            break;
            
        case KEY_PPAGE:
            scroll_content_up(5);
            break;
            
        case KEY_NPAGE:
            scroll_content_down(5);
            break;
            
        case KEY_HOME:
            scroll_content_top();
            break;
            
        case KEY_END:
            scroll_content_bottom();
            break;
            
        case '\n':
        case KEY_ENTER:
            switch (selected_item) {
                case MENU_USB_DEVICES:
                    show_usb_devices();
                    break;
                case MENU_PCI_DEVICES:
                    show_pci_devices();
                    break;
                case MENU_NETWORK_SCAN:
                    show_network_scan();
                    break;
                case MENU_NEARBY_DEVICES:
                    show_nearby_devices();
                    break;
                case MENU_BLUETOOTH:
                    show_bluetooth_devices();
                    break;
                case MENU_HARDWARE_INFO:
                    show_hardware_info();
                    break;
                case MENU_SYSTEM_INFO:
                    show_system_info();
                    break;
                case MENU_NETWORK_PROTOCOLS:
                    show_network_protocols();
                    break;
                case MENU_DATA_ANALYSIS:
                    show_data_analysis();
                    break;
                case MENU_HELP:
                    show_help();
                    break;
                case MENU_EXIT:
                    return;
            }
            break;
            
        case KEY_F(1):
            show_help();
            break;
            
        case 'q':
        case 'Q':
            return;
    }
}

void refresh_all(void) {
    draw_menu();
    draw_content();
    draw_status();
}

void ui_main_loop(void) {
    int ch;
    
    refresh_all();
    
    while ((ch = getch()) != 'q' && ch != 'Q') {
        handle_input(ch);
        refresh_all();
    }
}
