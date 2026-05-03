-- Network Scanner Module for Device Analyzer
-- Advanced network discovery and protocol analysis

local M = {}
M.version = "1.0"

-- Common service ports
M.common_ports = {
    21,   -- FTP
    22,   -- SSH
    23,   -- Telnet
    25,   -- SMTP
    53,   -- DNS
    80,   -- HTTP
    110,  -- POP3
    143,  -- IMAP
    443,  -- HTTPS
    445,  -- SMB
    3306, -- MySQL
    3389, -- RDP
    5432, -- PostgreSQL
    5900, -- VNC
    8080, -- HTTP Proxy
}

-- Service names lookup
M.services = {
    [21] = "FTP",
    [22] = "SSH",
    [23] = "Telnet",
    [25] = "SMTP",
    [53] = "DNS",
    [80] = "HTTP",
    [110] = "POP3",
    [143] = "IMAP",
    [443] = "HTTPS",
    [445] = "SMB/CIFS",
    [3306] = "MySQL",
    [3389] = "RDP",
    [5432] = "PostgreSQL",
    [5900] = "VNC",
    [8080] = "HTTP Proxy",
}

-- Get local network configuration
function M.get_network_config()
    local config = {}
    
    -- Get default gateway
    local f = io.open("/proc/net/route", "r")
    if f then
        local header = f:read("*line")
        for line in f:lines() do
            local iface, dest, gateway = line:match("^(%S+)%s+(%S+)%s+(%S+)")
            if iface and dest == "00000000" and gateway then
                config.gateway = gateway
                config.iface = iface
                break
            end
        end
        f:close()
    end
    
    return config
end

-- Parse CIDR notation
function M.parse_cidr(cidr)
    local ip, prefix = cidr:match("^([^/]+)/(%d+)$")
    if not ip then return nil end
    
    local parts = {}
    for part in ip:gmatch("%d+") do
        table.insert(parts, tonumber(part))
    end
    
    if #parts ~= 4 then return nil end
    
    prefix = tonumber(prefix)
    if not prefix or prefix < 0 or prefix > 32 then return nil end
    
    return {
        ip = parts,
        prefix = prefix,
        network = table.concat(parts, ".") .. "/" .. prefix
    }
end

-- Generate IP range from network
function M.get_ip_range(network)
    local parsed = M.parse_cidr(network)
    if not parsed then return nil end
    
    local host_bits = 32 - parsed.prefix
    local num_hosts = 2^host_bits - 2
    
    local start_ip = 0
    for i = 1, 4 do
        start_ip = start_ip * 256 + parsed.ip[i]
    end
    
    local network_addr = bit32.band(start_ip, bit32.lshift(0xFFFFFFFF, host_bits))
    local start_host = network_addr + 1
    local end_host = network_addr + num_hosts
    
    return {
        start = start_host,
        finish = end_host,
        count = num_hosts
    }
end

-- Convert integer to IP string
function M.int_to_ip(int)
    return string.format("%d.%d.%d.%d",
        bit32.rshift(int, 24) % 256,
        bit32.rshift(int, 16) % 256,
        bit32.rshift(int, 8) % 256,
        int % 256
    )
end

-- Scan a range of hosts with ping
function M.ping_scan(network)
    local range = M.get_ip_range(network)
    if not range then return {} end
    
    local results = {}
    
    for ip_int = range.start, math.min(range.finish, range.start + 254) do
        local ip = M.int_to_ip(ip_int)
        
        -- Non-blocking ping using system command
        local cmd = string.format("ping -c 1 -W 1 %s 2>/dev/null | grep -q 'bytes from' && echo 'up' || echo 'down'", ip)
        local handle = io.popen(cmd)
        local status = handle:read("*line")
        handle:close()
        
        if status == "up" then
            table.insert(results, {
                ip = ip,
                status = "alive",
                hostname = c_resolve_hostname(ip)
            })
        end
    end
    
    return results
end

-- Port scan on a specific host
function M.port_scan(host, ports)
    ports = ports or M.common_ports
    local open_ports = {}
    
    for _, port in ipairs(ports) do
        if c_scan_port(host, port) then
            table.insert(open_ports, {
                port = port,
                service = M.services[port] or "unknown"
            })
        end
    end
    
    return open_ports
end

-- Discover services via mDNS/DNS-SD
function M.discover_services()
    local services = {}
    
    -- Check for avahi/mDNS services
    local handle = io.popen("avahi-browse -a -t -p 2>/dev/null || echo ''")
    if handle then
        for line in handle:lines() do
            local parts = {}
            for part in line:gmatch("[^;]+") do
                table.insert(parts, part)
            end
            
            if #parts >= 4 then
                table.insert(services, {
                    interface = parts[1],
                    protocol = parts[2],
                    name = parts[3],
                    type = parts[4],
                    domain = parts[5] or "local"
                })
            end
        end
        handle:close()
    end
    
    return services
end

-- Analyze network protocols from /proc
function M.analyze_protocols()
    local protocols = {}
    
    -- Read protocol statistics
    local f = io.open("/proc/net/snmp", "r")
    if f then
        for line in f:lines() do
            if line:find("^%w+:") then
                table.insert(protocols, line)
            end
        end
        f:close()
    end
    
    return protocols
end

-- Get active connections
function M.get_connections()
    local connections = {}
    
    local f = io.open("/proc/net/tcp", "r")
    if f then
        local header = f:read("*line")
        for line in f:lines() do
            local parts = {}
            for part in line:gmatch("%S+") do
                table.insert(parts, part)
            end
            
            if #parts >= 4 then
                table.insert(connections, {
                    local_addr = parts[2],
                    rem_addr = parts[3],
                    state = parts[4],
                    inode = parts[10]
                })
            end
        end
        f:close()
    end
    
    return connections
end

-- Convert hex address to readable format
function M.decode_tcp_addr(hex)
    if not hex or #hex < 9 then return nil end
    
    local ip_hex = hex:sub(1, 8)
    local port_hex = hex:sub(10, 13)
    
    -- Convert IP (big endian to little endian)
    local ip = string.format("%d.%d.%d.%d",
        tonumber(ip_hex:sub(7, 8), 16),
        tonumber(ip_hex:sub(5, 6), 16),
        tonumber(ip_hex:sub(3, 4), 16),
        tonumber(ip_hex:sub(1, 2), 16)
    )
    
    local port = tonumber(port_hex, 16)
    
    return {ip = ip, port = port}
end

-- Get neighbor table (ARP/NDP)
function M.get_neighbors()
    return network.discover_arp()
end

-- SMB/CIFS discovery
function M.discover_smb()
    local shares = {}
    
    -- Use smbclient to discover shares
    local handle = io.popen("smbclient -L localhost -N 2>/dev/null | grep 'Disk' || echo ''")
    if handle then
        for line in handle:lines() do
            local share = line:match("^%s*(%S+)%s+Disk")
            if share then
                table.insert(shares, share)
            end
        end
        handle:close()
    end
    
    return shares
end

-- UPnP/SSDP discovery
function M.discover_upnp()
    local devices = {}
    
    -- Send SSDP M-SEARCH
    local ssdp_msg = table.concat({
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        "MAN: \"ssdp:discover\"",
        "MX: 3",
        "ST: ssdp:all",
        "",
        ""
    }, "\r\n")
    
    -- This requires UDP socket support
    -- For now, check for known UPnP services
    local handle = io.popen("timeout 2 gssdp-discover -t 3 2>/dev/null || echo ''")
    if handle then
        local output = handle:read("*all")
        handle:close()
        
        for line in output:gmatch("[^\r\n]+") do
            if line:find("USN:") or line:find("LOCATION:") then
                table.insert(devices, line)
            end
        end
    end
    
    return devices
end

-- WiFi сканирование через iwlist
function M.scan_wifi()
    local networks = {}
    
    -- получаем список wifi интерфейсов
    local handle = io.popen("iw dev 2>/dev/null | grep Interface | awk '{print $2}'")
    if not handle then return networks end
    
    local interfaces = {}
    for iface in handle:lines() do
        table.insert(interfaces, iface)
    end
    handle:close()
    
    -- сканируем каждый интерфейс
    for _, iface in ipairs(interfaces) do
        local scan_handle = io.popen("iwlist " .. iface .. " scan 2>/dev/null || echo ''")
        if scan_handle then
            local output = scan_handle:read("*all")
            scan_handle:close()
            
            local current_net = {}
            for line in output:gmatch("[^\n]+") do
                -- парсинг cell
                local cell = line:match("Cell %d+ - Address: ([%x:]+)")
                if cell then
                    if current_net.address then
                        table.insert(networks, current_net)
                    end
                    current_net = {address = cell, iface = iface}
                end
                
                -- парсинг essid
                local essid = line:match("ESSID:\"([^\"]+)\"")
                if essid then
                    current_net.name = essid
                end
                
                -- парсинг channel
                local channel = line:match("Channel:(%d+)")
                if channel then
                    current_net.channel = tonumber(channel)
                end
                
                -- парсинг frequency
                local freq = line:match("Frequency:([%d%.]+) GHz")
                if freq then
                    current_net.frequency = tonumber(freq)
                end
                
                -- парсинг signal level
                local signal = line:match("Signal level[=:](%-?%d+)")
                if signal then
                    current_net.signal = tonumber(signal)
                end
                
                -- парсинг encryption
                if line:find("Encryption key:on") then
                    current_net.encrypted = true
                elseif line:find("Encryption key:off") then
                    current_net.encrypted = false
                end
            end
            
            -- добавляем последнюю сеть
            if current_net.address then
                table.insert(networks, current_net)
            end
        end
    end
    
    return networks
end

-- анализ трафика через /proc/net/dev
function M.analyze_traffic()
    local stats = {}
    
    local f = io.open("/proc/net/dev", "r")
    if not f then return stats end
    
    -- пропускаем заголовки
    f:read("*line")
    f:read("*line")
    
    for line in f:lines() do
        local iface, rx_bytes, rx_packets, rx_errs, rx_drop, _, _, _, _, 
              tx_bytes, tx_packets, tx_errs, tx_drop = line:match(
            "^%s*(%S+):%s*(%d+)%s*(%d+)%s*(%d+)%s*(%d+)%s*%d+%s*%d+%s*%d+%s*%d+%s*(%d+)%s*(%d+)%s*(%d+)%s*(%d+)"
        )
        
        if iface then
            table.insert(stats, {
                interface = iface,
                rx_bytes = tonumber(rx_bytes) or 0,
                rx_packets = tonumber(rx_packets) or 0,
                rx_errors = tonumber(rx_errs) or 0,
                rx_dropped = tonumber(rx_drop) or 0,
                tx_bytes = tonumber(tx_bytes) or 0,
                tx_packets = tonumber(tx_packets) or 0,
                tx_errors = tonumber(tx_errs) or 0,
                tx_dropped = tonumber(tx_drop) or 0
            })
        end
    end
    
    f:close()
    return stats
end

-- traceroute упрощенный
function M.traceroute(host, max_hops)
    max_hops = max_hops or 30
    local hops = {}
    
    for ttl = 1, max_hops do
        -- используем ping с установкой ttl
        local cmd = string.format("ping -c 1 -t %d -W 2 %s 2>/dev/null | grep -o 'from [%d%.]*' | head -1", ttl, host, ttl)
        local handle = io.popen(cmd)
        local result = handle:read("*line")
        handle:close()
        
        if result then
            local hop_ip = result:match("from%s+([%d%.]+)")
            if hop_ip then
                table.insert(hops, {
                    hop = ttl,
                    ip = hop_ip,
                    hostname = c_resolve_hostname(hop_ip) or hop_ip
                })
                
                -- достигли цели
                if hop_ip == host then
                    break
                end
            end
        else
            table.insert(hops, {hop = ttl, ip = "*", hostname = "timeout"})
        end
    end
    
    return hops
end

-- информация о dhcp
function M.get_dhcp_info()
    local info = {}
    
    -- проверяем lease файлы
    local lease_files = {
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhclient/dhclient.leases",
        "/var/lib/NetworkManager/dhclient.leases"
    }
    
    for _, file in ipairs(lease_files) do
        local f = io.open(file, "r")
        if f then
            local content = f:read("*all")
            f:close()
            
            -- парсим lease
            for lease_block in content:gmatch("lease%s+{(.-)}%s*}") do
                local lease = {}
                
                local ip = lease_block:match("lease%s+([%d%.]+)")
                if ip then lease.ip = ip end
                
                local router = lease_block:match("option%s+routers%s+([%d%.]+)")
                if router then lease.router = router end
                
                local subnet = lease_block:match("option%s+subnet%-mask%s+([%d%.]+)")
                if subnet then lease.subnet = subnet end
                
                local dns = lease_block:match("option%s+domain%-name%-servers%s+([%d%. ,]+);")
                if dns then lease.dns = dns end
                
                local server = lease_block:match("server%-name%s+\"([^\"]+)\"")
                if server then lease.server = server end
                
                table.insert(info, lease)
            end
        end
    end
    
    return info
end

-- обнаружение ближайших bluetooth устройств
function M.scan_bluetooth()
    local devices = {}
    
    -- проверяем доступность bluetooth
    local check_handle = io.popen("which hcitool 2>/dev/null")
    local has_hcitool = check_handle:read("*line")
    check_handle:close()
    
    if not has_hcitool or has_hcitool == "" then
        return {error = "hcitool not found, install bluez-utils"}
    end
    
    -- сканирование
    local handle = io.popen("timeout 10 hcitool scan 2>/dev/null || echo ''")
    if handle then
        -- пропускаем заголовок
        handle:read("*line")
        
        for line in handle:lines() do
            local mac, name = line:match("^%s*([%x:]+)%s+(.+)$")
            if mac and name then
                table.insert(devices, {
                    mac = mac,
                    name = name,
                    type = "classic"
                })
            end
        end
        handle:close()
    end
    
    -- ble сканирование через bluetoothctl
    local ble_handle = io.popen("timeout 10 bluetoothctl scan on 2>/dev/null & sleep 5 && bluetoothctl devices | head -20 || echo ''")
    if ble_handle then
        for line in ble_handle:lines() do
            local mac, name = line:match("Device%s+([%x:]+)%s+(.+)$")
            if mac then
                -- проверяем есть ли уже
                local found = false
                for _, d in ipairs(devices) do
                    if d.mac == mac then
                        found = true
                        break
                    end
                end
                if not found then
                    table.insert(devices, {
                        mac = mac,
                        name = name or "Unknown BLE",
                        type = "ble"
                    })
                end
            end
        end
        ble_handle:close()
    end
    
    return devices
end

-- полное сетевое сканирование
function M.full_network_scan()
    local results = {
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
        local_config = M.get_network_config(),
        interfaces = {},
        arp_table = M.get_neighbors(),
        services = M.discover_services(),
        upnp_devices = M.discover_upnp(),
        smb_shares = M.discover_smb(),
        wifi_networks = M.scan_wifi(),
        traffic_stats = M.analyze_traffic(),
        protocols = M.analyze_protocols(),
        connections = M.get_connections()
    }
    
    -- информация об интерфейсах
    local f = io.open("/proc/net/dev", "r")
    if f then
        f:read("*line")
        f:read("*line")
        for line in f:lines() do
            local iface = line:match("^%s*(%S+):")
            if iface then
                table.insert(results.interfaces, iface)
            end
        end
        f:close()
    end
    
    return results
end

return M
