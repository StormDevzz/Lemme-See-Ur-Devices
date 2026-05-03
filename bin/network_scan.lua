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
        
        for line in output:gmatch("[^
]+") do
            if line:find("USN:") or line:find("LOCATION:") then
                table.insert(devices, line)
            end
        end
    end
    
    return devices
end

return M
