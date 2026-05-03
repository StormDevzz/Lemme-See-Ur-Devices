#ifndef LUA_BRIDGE_H
#define LUA_BRIDGE_H

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

// функции lua моста
int lua_bridge_init(void);
void lua_bridge_cleanup(void);

// сетевой анализ через lua
char* lua_network_scan(void);
char* lua_analyze_protocols(void);
char* lua_scan_ports(const char *host, int start_port, int end_port);
char* lua_discover_mdns(void);
char* lua_get_network_stats(void);

// обнаружение bluetooth и устройств рядом
char* lua_bluetooth_scan(void);
char* lua_nearby_devices_scan(void);
char* lua_upnp_discovery(void);
char* lua_wifi_devices_scan(void);

// выполнение lua кода и возврат строки
char* lua_execute_script(const char *script_path);
char* lua_execute_code(const char *code);

#endif // lua_bridge_h
