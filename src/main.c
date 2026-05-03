/*
 * Device Analyzer - Main Entry Point
 * Linux device discovery and analysis tool
 * Multi-language architecture: C, ASM, Lua, Python
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <signal.h>
#include "ui.h"
#include "usb_scanner.h"
#include "hardware_info.h"
#include "lua_bridge.h"
#include "python_bridge.h"

static volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Device Analyzer - Initializing...\n");
    
    // Initialize subsystems
    if (ui_init() != 0) {
        fprintf(stderr, "Failed to initialize UI\n");
        return 1;
    }
    
    if (usb_scanner_init() != 0) {
        fprintf(stderr, "Failed to initialize USB scanner\n");
        ui_cleanup();
        return 1;
    }
    
    if (lua_bridge_init() != 0) {
        fprintf(stderr, "Failed to initialize Lua bridge\n");
        usb_scanner_cleanup();
        ui_cleanup();
        return 1;
    }
    
    if (python_bridge_init() != 0) {
        fprintf(stderr, "Warning: Python bridge failed to initialize\n");
    }
    
    // Run main UI loop
    ui_main_loop();
    
    // Cleanup
    python_bridge_cleanup();
    lua_bridge_cleanup();
    usb_scanner_cleanup();
    ui_cleanup();
    
    printf("Device Analyzer - Shutdown complete\n");
    return 0;
}
