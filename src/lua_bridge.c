/*
 * Lua Bridge Module
 * Network analysis and protocol inspection via Lua
 */

#include "lua_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>

static lua_State *L = NULL;

// C functions exposed to Lua
static int l_get_local_ip(lua_State *L);
static int l_get_interfaces(lua_State *L);
static int l_ping_host(lua_State *L);
static int l_resolve_hostname(lua_State *L);
static int l_scan_port(lua_State *L);

int lua_bridge_init(void) {
    L = luaL_newstate();
    if (!L) {
        return -1;
    }
    
    luaL_openlibs(L);
    
    // Register C functions for Lua
    lua_pushcfunction(L, l_get_local_ip);
    lua_setglobal(L, "c_get_local_ip");
    
    lua_pushcfunction(L, l_get_interfaces);
    lua_setglobal(L, "c_get_interfaces");
    
    lua_pushcfunction(L, l_ping_host);
    lua_setglobal(L, "c_ping_host");
    
    lua_pushcfunction(L, l_resolve_hostname);
    lua_setglobal(L, "c_resolve_hostname");
    
    lua_pushcfunction(L, l_scan_port);
    lua_setglobal(L, "c_scan_port");
    
    // Load embedded Lua scripts
    const char *init_script = 
        "network = {}\n"
        "network.scan_results = {}\n"
        "\n"
        "function network.get_local_info()\n"
        "    local info = {}\n"
        "    info.interfaces = c_get_interfaces()\n"
        "    info.hostname = io.popen('hostname'):read('*line')\n"
        "    return info\n"
        "end\n"
        "\n"
        "function network.ping_sweep(subnet)\n"
        "    local results = {}\n"
        "    for i = 1, 254 do\n"
        "        local host = subnet .. '.' .. i\n"
        "        local status = c_ping_host(host, 100)\n"
        "        if status then\n"
        "            table.insert(results, {ip = host, alive = true})\n"
        "        end\n"
        "    end\n"
        "    return results\n"
        "end\n"
        "\n"
        "function network.analyze_protocols()\n"
        "    local protocols = {}\n"
        "    -- Read /proc/net for protocol stats\n"
        "    local f = io.open('/proc/net/protocols', 'r')\n"
        "    if f then\n"
        "        for line in f:lines() do\n"
        "            table.insert(protocols, line)\n"
        "        end\n"
        "        f:close()\n"
        "    end\n"
        "    return protocols\n"
        "end\n"
        "\n"
        "function network.get_netstat()\n"
        "    local stats = {}\n"
        "    local f = io.open('/proc/net/netstat', 'r')\n"
        "    if f then\n"
        "        for line in f:lines() do\n"
        "            table.insert(stats, line)\n"
        "        end\n"
        "        f:close()\n"
        "    end\n"
        "    return stats\n"
        "end\n"
        "\n"
        "function network.scan_service_ports(host, ports)\n"
        "    local results = {}\n"
        "    for _, port in ipairs(ports) do\n"
        "        local open = c_scan_port(host, port)\n"
        "        if open then\n"
        "            table.insert(results, {port = port, state = 'open'})\n"
        "        end\n"
        "    end\n"
        "    return results\n"
        "end\n"
        "\n"
        "function network.discover_arp()\n"
        "    local arp_table = {}\n"
        "    local f = io.open('/proc/net/arp', 'r')\n"
        "    if f then\n"
        "        local header = f:read('*line')\n"
        "        for line in f:lines() do\n"
        "            local ip, hw_type, flags, hw_addr, mask, device =\n"
        "                line:match('([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+([^%s]+)%s+([^%s]+)')\n"
        "            if ip then\n"
        "                table.insert(arp_table, {\n"
        "                    ip = ip,\n"
        "                    mac = hw_addr,\n"
        "                    interface = device,\n"
        "                    flags = flags\n"
        "                })\n"
        "            end\n"
        "        end\n"
        "        f:close()\n"
        "    end\n"
        "    return arp_table\n"
        "end\n";
    
    if (luaL_dostring(L, init_script) != LUA_OK) {
        fprintf(stderr, "Lua init error: %s\n", lua_tostring(L, -1));
        lua_pop(L, 1);
    }
    
    return 0;
}

void lua_bridge_cleanup(void) {
    if (L) {
        lua_close(L);
        L = NULL;
    }
}

char* lua_network_scan(void) {
    if (!L) return strdup("Lua not initialized");
    
    char *result = malloc(8192);
    if (!result) return NULL;
    
    strcpy(result, "Network Discovery (Lua-powered)\n");
    strcat(result, "===============================\n\n");
    
    // Get local interfaces
    lua_getglobal(L, "network");
    lua_getfield(L, -1, "get_local_info");
    lua_remove(L, -2);
    
    if (lua_pcall(L, 0, 1, 0) == LUA_OK) {
        if (lua_istable(L, -1)) {
            lua_getfield(L, -1, "hostname");
            if (lua_isstring(L, -1)) {
                snprintf(result + strlen(result), 512, "Hostname: %s\n", lua_tostring(L, -1));
            }
            lua_pop(L, 1);
            
            lua_getfield(L, -1, "interfaces");
            if (lua_istable(L, -1)) {
                strcat(result, "\nNetwork Interfaces:\n");
                lua_pushnil(L);
                while (lua_next(L, -2) != 0) {
                    if (lua_istable(L, -1)) {
                        lua_getfield(L, -1, "name");
                        lua_getfield(L, -2, "ip");
                        const char *name = lua_tostring(L, -2);
                        const char *ip = lua_tostring(L, -1);
                        if (name && ip) {
                            snprintf(result + strlen(result), 512, "  %s: %s\n", name, ip);
                        }
                        lua_pop(L, 2);
                    }
                    lua_pop(L, 1);
                }
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    } else {
        strcat(result, "Error calling get_local_info\n");
        lua_pop(L, 1);
    }
    
    // Discover ARP table
    lua_getglobal(L, "network");
    lua_getfield(L, -1, "discover_arp");
    lua_remove(L, -2);
    
    if (lua_pcall(L, 0, 1, 0) == LUA_OK) {
        if (lua_istable(L, -1)) {
            strcat(result, "\n--- ARP Table ---\n");
            int n = lua_rawlen(L, -1);
            for (int i = 1; i <= n && i <= 20; i++) {
                lua_rawgeti(L, -1, i);
                if (lua_istable(L, -1)) {
                    lua_getfield(L, -1, "ip");
                    lua_getfield(L, -2, "mac");
                    lua_getfield(L, -3, "interface");
                    const char *ip = lua_tostring(L, -3);
                    const char *mac = lua_tostring(L, -2);
                    const char *iface = lua_tostring(L, -1);
                    if (ip && mac) {
                        snprintf(result + strlen(result), 512, "  %s -> %s (%s)\n", ip, mac, iface ? iface : "?");
                    }
                    lua_pop(L, 3);
                }
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);
    } else {
        lua_pop(L, 1);
    }
    
    return result;
}

char* lua_analyze_protocols(void) {
    if (!L) return strdup("Lua not initialized");
    
    char *result = malloc(4096);
    if (!result) return NULL;
    
    strcpy(result, "Protocol Analysis (Lua-powered)\n");
    strcat(result, "================================\n\n");
    
    lua_getglobal(L, "network");
    lua_getfield(L, -1, "analyze_protocols");
    lua_remove(L, -2);
    
    if (lua_pcall(L, 0, 1, 0) == LUA_OK) {
        if (lua_istable(L, -1)) {
            int n = lua_rawlen(L, -1);
            for (int i = 1; i <= n && i <= 30; i++) {
                lua_rawgeti(L, -1, i);
                if (lua_isstring(L, -1)) {
                    strncat(result, lua_tostring(L, -1), 4096 - strlen(result) - 1);
                    strcat(result, "\n");
                }
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);
    } else {
        strcat(result, "Error analyzing protocols\n");
        lua_pop(L, 1);
    }
    
    return result;
}

char* lua_get_network_stats(void) {
    if (!L) return strdup("Lua not initialized");
    
    char *result = malloc(4096);
    if (!result) return NULL;
    
    strcpy(result, "Network Statistics (Lua-powered)\n");
    strcat(result, "=================================\n\n");
    
    lua_getglobal(L, "network");
    lua_getfield(L, -1, "get_netstat");
    lua_remove(L, -2);
    
    if (lua_pcall(L, 0, 1, 0) == LUA_OK) {
        if (lua_istable(L, -1)) {
            int n = lua_rawlen(L, -1);
            for (int i = 1; i <= n && i <= 50; i++) {
                lua_rawgeti(L, -1, i);
                if (lua_isstring(L, -1)) {
                    strncat(result, lua_tostring(L, -1), 4096 - strlen(result) - 1);
                    strcat(result, "\n");
                }
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);
    } else {
        strcat(result, "Error getting network stats\n");
        lua_pop(L, 1);
    }
    
    return result;
}

char* lua_discover_mdns(void) {
    // mDNS/Bonjour discovery
    char *result = malloc(4096);
    if (!result) return NULL;
    
    strcpy(result, "mDNS/Bonjour Discovery\n");
    strcat(result, "=======================\n\n");
    
    // Try avahi-browse if available
    FILE *fp = popen("avahi-browse -a -t -p 2>/dev/null | head -20 || echo 'avahi-browse not available'", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(result, line, 4096 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    return result;
}

// C function implementations for Lua

static int l_get_local_ip(lua_State *L) {
    struct ifaddrs *ifaddr, *ifa;
    char addr_str[INET6_ADDRSTRLEN];
    
    if (getifaddrs(&ifaddr) == -1) {
        lua_pushnil(L);
        return 1;
    }
    
    lua_newtable(L);
    int index = 1;
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        void *addr_ptr = NULL;
        const char *family_name = NULL;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            addr_ptr = &sin->sin_addr;
            family_name = "IPv4";
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            addr_ptr = &sin6->sin6_addr;
            family_name = "IPv6";
        } else {
            continue;
        }
        
        inet_ntop(ifa->ifa_addr->sa_family, addr_ptr, addr_str, sizeof(addr_str));
        
        lua_newtable(L);
        lua_pushstring(L, ifa->ifa_name);
        lua_setfield(L, -2, "name");
        lua_pushstring(L, addr_str);
        lua_setfield(L, -2, "ip");
        lua_pushstring(L, family_name);
        lua_setfield(L, -2, "family");
        lua_rawseti(L, -2, index++);
    }
    
    freeifaddrs(ifaddr);
    return 1;
}

static int l_get_interfaces(lua_State *L) {
    return l_get_local_ip(L);
}

static int l_ping_host(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int timeout_ms = luaL_optinteger(L, 2, 1000);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W %d %s 2>/dev/null | grep -q 'bytes from'", 
             (timeout_ms + 999) / 1000, host);
    
    int status = system(cmd);
    lua_pushboolean(L, status == 0);
    return 1;
}

static int l_resolve_hostname(lua_State *L) {
    const char *hostname = luaL_checkstring(L, 1);
    
    struct hostent *he = gethostbyname(hostname);
    if (he && he->h_addr_list[0]) {
        struct in_addr addr;
        memcpy(&addr, he->h_addr_list[0], sizeof(addr));
        lua_pushstring(L, inet_ntoa(addr));
        return 1;
    }
    
    lua_pushnil(L);
    return 1;
}

static int l_scan_port(lua_State *L) {
    const char *host = luaL_checkstring(L, 1);
    int port = luaL_checkinteger(L, 2);
    int timeout_ms = luaL_optinteger(L, 3, 500);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        lua_pushboolean(L, 0);
        return 1;
    }
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    
    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    
    lua_pushboolean(L, result == 0);
    return 1;
}

char* lua_bluetooth_scan(void) {
    char *result = malloc(16384);
    if (!result) return NULL;
    
    strcpy(result, "Bluetooth Device Discovery\n");
    strcat(result, "==========================\n\n");
    
    // Check if Bluetooth adapter exists and is powered on
    FILE *fp = popen("hciconfig 2>/dev/null | grep -E 'hci|UP|DOWN' | head -5 || echo 'No adapter found'", "r");
    if (fp) {
        strcat(result, "--- Adapter Status ---\n");
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(result, line, 16384 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    // Power on adapter if needed
    system("bluetoothctl power on 2>/dev/null");
    
    // Start discovery mode
    system("bluetoothctl agent on 2>/dev/null");
    system("bluetoothctl default-agent 2>/dev/null");
    
    // Scan with bluetoothctl (longer timeout for phones)
    strcat(result, "\n--- Scanning for 15 seconds... ---\n");
    strcat(result, "(Make sure your phone is in DISCOVERABLE mode)\n\n");
    
    // Run scan and capture output
    fp = popen("timeout 15 bluetoothctl scan on 2>&1 | grep -E 'Device|NEW|DEL|Found|Controller' | head -40", "r");
    if (fp) {
        char line[512];
        int found = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strlen(line) > 5) {
                // Classify device type
                if (strstr(line, "Phone") || strstr(line, "phone") || strstr(line, "iPhone")) {
                    strncat(result, "[PHONE] ", 16384 - strlen(result) - 1);
                } else if (strstr(line, "Audio") || strstr(line, "Headset") || strstr(line, "Speaker")) {
                    strncat(result, "[AUDIO] ", 16384 - strlen(result) - 1);
                } else if (strstr(line, "Keyboard") || strstr(line, "Mouse")) {
                    strncat(result, "[HID] ", 16384 - strlen(result) - 1);
                } else if (strstr(line, "Computer") || strstr(line, "Laptop")) {
                    strncat(result, "[PC] ", 16384 - strlen(result) - 1);
                }
                strcat(result, line);
                found = 1;
            }
        }
        pclose(fp);
        
        if (!found) {
            strcat(result, "No devices found during scan.\n\n");
            strcat(result, "TROUBLESHOOTING:\n");
            strcat(result, "1. Is your phone in DISCOVERABLE mode?\n");
            strcat(result, "   - Android: Settings > Bluetooth > (3 dots) > Make visible\n");
            strcat(result, "   - iPhone: Settings > Bluetooth (visible while this screen open)\n");
            strcat(result, "2. Is laptop Bluetooth enabled?\n");
            strcat(result, "3. Are devices within 10 meters?\n\n");
        }
    }
    
    // Try hcitool lescan (BLE devices - modern phones)
    strcat(result, "--- BLE (Low Energy) Scan ---\n");
    fp = popen("timeout 10 hcitool lescan 2>/dev/null | grep -v 'LE Scan' | head -20 || echo 'BLE scan not available'", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            strncat(result, line, 16384 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    // Get paired/trusted devices (phones usually pair)
    strcat(result, "\n--- Paired/Trusted Devices ---\n");
    fp = popen("bluetoothctl devices 2>/dev/null | head -30 || echo ''", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strlen(line) > 10) {
                strncat(result, line, 16384 - strlen(result) - 1);
            }
        }
        pclose(fp);
    }
    
    // Device info from bluetoothctl
    strcat(result, "\n--- Device Details (if any paired) ---\n");
    fp = popen("bluetoothctl info 2>/dev/null | head -20 || echo ''", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            strncat(result, line, 16384 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    return result;
}

char* lua_nearby_devices_scan(void) {
    char *result = malloc(16384);
    if (!result) return NULL;
    
    strcpy(result, "Nearby Device Discovery (Phones, IoT, Smart Devices)\n");
    strcat(result, "=====================================================\n\n");
    
    // mDNS/Bonjour discovery for phones, TVs, printers, etc.
    strcat(result, "--- mDNS/Bonjour Services (Phones, TVs, Printers) ---\n");
    FILE *fp = popen("timeout 10 avahi-browse -a -t -p 2>/dev/null | head -40 || echo 'avahi-browse not available'", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            // Parse avahi output to identify device types
            if (strstr(line, "_googlecast") || strstr(line, "_airplay") || 
                strstr(line, "_raop") || strstr(line, "_mediaremotetv")) {
                strncat(result, "[TV/Streaming] ", 16384 - strlen(result) - 1);
            } else if (strstr(line, "_ios") || strstr(line, "_apple") || strstr(line, "_airdrop")) {
                strncat(result, "[Apple Device] ", 16384 - strlen(result) - 1);
            } else if (strstr(line, "_android") || strstr(line, "_google")) {
                strncat(result, "[Android Device] ", 16384 - strlen(result) - 1);
            } else if (strstr(line, "_printer") || strstr(line, "_ipp") || strstr(line, "_pdl-datastream")) {
                strncat(result, "[Printer] ", 16384 - strlen(result) - 1);
            } else if (strstr(line, "_http") || strstr(line, "_webdav")) {
                strncat(result, "[Web Service] ", 16384 - strlen(result) - 1);
            } else if (strstr(line, "_ssh") || strstr(line, "_sftp")) {
                strncat(result, "[SSH/SFTP] ", 16384 - strlen(result) - 1);
            } else if (strstr(line, "_ smb") || strstr(line, "_cifs")) {
                strncat(result, "[File Sharing] ", 16384 - strlen(result) - 1);
            }
            strncat(result, line, 16384 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    // UPnP/SSDP discovery
    strcat(result, "\n--- UPnP/SSDP Devices (Routers, Smart Home) ---\n");
    fp = popen("timeout 8 gssdp-discover -t 5 2>/dev/null | head -30 || timeout 8 ssdp-discover 2>/dev/null | head -30 || echo 'UPnP discovery not available'", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "Router") || strstr(line, "router")) {
                strncat(result, "[ROUTER] ", 16384 - strlen(result) - 1);
            } else if (strstr(line, "MediaServer") || strstr(line, "ContentDirectory")) {
                strncat(result, "[NAS/Media Server] ", 16384 - strlen(result) - 1);
            } else if (strstr(line, "InternetGatewayDevice")) {
                strncat(result, "[Gateway] ", 16384 - strlen(result) - 1);
            }
            strncat(result, line, 16384 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    // WiFi neighbors via iw/iwlist
    strcat(result, "\n--- WiFi Networks (Nearby Access Points) ---\n");
    fp = popen("iw dev 2>/dev/null | grep Interface | head -1 | awk '{print $2}'", "r");
    char iface[64] = {0};
    if (fp && fgets(iface, sizeof(iface), fp)) {
        iface[strcspn(iface, "\n")] = 0;
        pclose(fp);
        
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "iwlist %s scan 2>/dev/null | grep -E 'Address|ESSID|Signal|Channel' | head -30 || echo ''", iface);
        fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                strncat(result, line, 16384 - strlen(result) - 1);
            }
            pclose(fp);
        }
    } else {
        if (fp) pclose(fp);
        strcat(result, "WiFi interface not found or iwlist not available\n");
    }
    
    // ARP table - recently active devices
    strcat(result, "\n--- Recently Active Devices (ARP Table) ---\n");
    fp = popen("cat /proc/net/arp 2>/dev/null | grep -v 'IP address' | head -20 || echo ''", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            // Parse MAC address to identify vendor
            char mac[18];
            if (sscanf(line, "%*s %*s %*s %17s", mac) == 1) {
                char vendor[64] = "";
                // Check for common MAC prefixes
                if (strncmp(mac, "00:50:56", 8) == 0 || strncmp(mac, "00:0c:29", 8) == 0 || strncmp(mac, "00:05:69", 8) == 0) {
                    strcpy(vendor, " [VMware]");
                } else if (strncmp(mac, "b8:27:eb", 8) == 0 || strncmp(mac, "dc:a6:32", 8) == 0) {
                    strcpy(vendor, " [Raspberry Pi]");
                } else if (strncmp(mac, "3c:5a:b4", 8) == 0 || strncmp(mac, "ac:de:48", 8) == 0 || strncmp(mac, "f0:18:98", 8) == 0) {
                    strcpy(vendor, " [Apple]");
                } else if (strncmp(mac, "00:1a:11", 8) == 0 || strncmp(mac, "90:18:7c", 8) == 0) {
                    strcpy(vendor, " [Google/Nest]");
                } else if (strncmp(mac, "a4:77:33", 8) == 0 || strncmp(mac, "50:ec:50", 8) == 0) {
                    strcpy(vendor, " [Amazon/Echo]");
                } else if (strncmp(mac, "00:17:88", 8) == 0 || strncmp(mac, "00:04:4b", 8) == 0) {
                    strcpy(vendor, " [Philips Hue]");
                }
                // Append vendor to line
                line[strcspn(line, "\n")] = 0;
                strcat(line, vendor);
                strcat(line, "\n");
            }
            strncat(result, line, 16384 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    return result;
}

char* lua_upnp_discovery(void) {
    return lua_nearby_devices_scan();
}

char* lua_wifi_devices_scan(void) {
    char *result = malloc(8192);
    if (!result) return NULL;
    
    strcpy(result, "WiFi Device Scan\n");
    strcat(result, "=================\n\n");
    
    // List available WiFi interfaces
    FILE *fp = popen("iw dev 2>/dev/null | grep -E 'Interface|type' | head -20 || echo 'iw not available'", "r");
    if (fp) {
        strcat(result, "WiFi Interfaces:\n");
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(result, line, 8192 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    // Current connection info
    fp = popen("iw dev 2>/dev/null | grep -A5 'Interface' | grep -E 'ssid|Interface' | head -10 || echo ''", "r");
    if (fp) {
        strcat(result, "\nCurrent Connection:\n");
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            strncat(result, line, 8192 - strlen(result) - 1);
        }
        pclose(fp);
    }
    
    return result;
}

char* lua_execute_script(const char *script_path) {
    if (!L) return strdup("Lua not initialized");
    
    if (luaL_dofile(L, script_path) != LUA_OK) {
        const char *error = lua_tostring(L, -1);
        char *result = malloc(strlen(error) + 64);
        sprintf(result, "Error: %s", error);
        lua_pop(L, 1);
        return result;
    }
    
    return strdup("Script executed successfully");
}

char* lua_execute_code(const char *code) {
    if (!L) return strdup("Lua not initialized");
    
    if (luaL_dostring(L, code) != LUA_OK) {
        const char *error = lua_tostring(L, -1);
        char *result = malloc(strlen(error) + 64);
        sprintf(result, "Error: %s", error);
        lua_pop(L, 1);
        return result;
    }
    
    return strdup("Code executed successfully");
}
