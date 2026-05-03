#ifndef LUA_BRIDGE_H
#define LUA_BRIDGE_H

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

// Lua bridge functions
int lua_bridge_init(void);
void lua_bridge_cleanup(void);

// Network analysis via Lua
char* lua_network_scan(void);
char* lua_analyze_protocols(void);
char* lua_scan_ports(const char *host, int start_port, int end_port);
char* lua_discover_mdns(void);
char* lua_get_network_stats(void);

// Bluetooth and nearby device discovery
char* lua_bluetooth_scan(void);
char* lua_nearby_devices_scan(void);
char* lua_upnp_discovery(void);
char* lua_wifi_devices_scan(void);

// Execute Lua code and return string result
char* lua_execute_script(const char *script_path);
char* lua_execute_code(const char *code);

#endif // LUA_BRIDGE_H
