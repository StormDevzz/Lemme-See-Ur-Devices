-- Protocol Analyzer Module
-- Deep packet inspection and protocol decoding

local M = {}

-- Ethernet protocol types
M.ethertypes = {
    [0x0800] = "IPv4",
    [0x0806] = "ARP",
    [0x86DD] = "IPv6",
    [0x8100] = "VLAN",
    [0x8847] = "MPLS",
    [0x88CC] = "LLDP",
    [0x8906] = "FCoE",
}

-- IP protocol numbers
M.ip_protocols = {
    [1] = "ICMP",
    [2] = "IGMP",
    [6] = "TCP",
    [17] = "UDP",
    [41] = "IPv6",
    [47] = "GRE",
    [50] = "ESP",
    [51] = "AH",
    [58] = "ICMPv6",
    [89] = "OSPF",
    [132] = "SCTP",
}

-- TCP flag names
M.tcp_flags = {
    [0x01] = "FIN",
    [0x02] = "SYN",
    [0x04] = "RST",
    [0x08] = "PSH",
    [0x10] = "ACK",
    [0x20] = "URG",
    [0x40] = "ECE",
    [0x80] = "CWR",
}

-- Well-known port services
M.well_known_ports = {
    [7] = "echo",
    [20] = "ftp-data",
    [21] = "ftp",
    [22] = "ssh",
    [23] = "telnet",
    [25] = "smtp",
    [53] = "domain",
    [67] = "dhcp-server",
    [68] = "dhcp-client",
    [80] = "http",
    [110] = "pop3",
    [119] = "nntp",
    [123] = "ntp",
    [135] = "msrpc",
    [139] = "netbios-ssn",
    [143] = "imap",
    [161] = "snmp",
    [162] = "snmptrap",
    [443] = "https",
    [445] = "microsoft-ds",
    [514] = "syslog",
    [515] = "printer",
    [520] = "rip",
    [587] = "smtp-submission",
    [631] = "ipp",
    [636] = "ldaps",
    [989] = "ftps-data",
    [990] = "ftps",
    [993] = "imaps",
    [995] = "pop3s",
    [1080] = "socks",
    [1433] = "ms-sql-s",
    [1434] = "ms-sql-m",
    [3306] = "mysql",
    [3389] = "ms-wbt-server",
    [5432] = "postgresql",
    [5900] = "vnc",
    [6379] = "redis",
    [8080] = "http-proxy",
    [8443] = "https-alt",
    [9200] = "elasticsearch",
    [9300] = "elasticsearch-transport",
}

-- Decode ethernet frame header
function M.decode_eth_header(data)
    if #data < 14 then return nil end
    
    local dst_mac = data:sub(1, 6):gsub(".", function(c)
        return string.format("%02x:", string.byte(c))
    end):sub(1, -2)
    
    local src_mac = data:sub(7, 12):gsub(".", function(c)
        return string.format("%02x:", string.byte(c))
    end):sub(1, -2)
    
    local ethertype = string.byte(data, 13) * 256 + string.byte(data, 14)
    
    return {
        dst_mac = dst_mac,
        src_mac = src_mac,
        ethertype = ethertype,
        ethertype_name = M.ethertypes[ethertype] or "Unknown",
        payload = data:sub(15)
    }
end

-- Decode IP packet header
function M.decode_ip_header(data)
    if #data < 20 then return nil end
    
    local version_ihl = string.byte(data, 1)
    local version = bit32.rshift(version_ihl, 4)
    local ihl = bit32.band(version_ihl, 0x0F) * 4
    
    local tos = string.byte(data, 2)
    local total_length = string.byte(data, 3) * 256 + string.byte(data, 4)
    local identification = string.byte(data, 5) * 256 + string.byte(data, 6)
    local flags_fragment = string.byte(data, 7) * 256 + string.byte(data, 8)
    local ttl = string.byte(data, 9)
    local protocol = string.byte(data, 10)
    local checksum = string.byte(data, 11) * 256 + string.byte(data, 12)
    
    local src_ip = table.concat({
        string.byte(data, 13),
        string.byte(data, 14),
        string.byte(data, 15),
        string.byte(data, 16)
    }, ".")
    
    local dst_ip = table.concat({
        string.byte(data, 17),
        string.byte(data, 18),
        string.byte(data, 19),
        string.byte(data, 20)
    }, ".")
    
    return {
        version = version,
        header_length = ihl,
        tos = tos,
        total_length = total_length,
        identification = identification,
        flags = bit32.rshift(flags_fragment, 13),
        fragment_offset = bit32.band(flags_fragment, 0x1FFF),
        ttl = ttl,
        protocol = protocol,
        protocol_name = M.ip_protocols[protocol] or "Unknown",
        checksum = checksum,
        src_ip = src_ip,
        dst_ip = dst_ip,
        payload = data:sub(ihl + 1)
    }
end

-- Decode TCP header
function M.decode_tcp_header(data)
    if #data < 20 then return nil end
    
    local src_port = string.byte(data, 1) * 256 + string.byte(data, 2)
    local dst_port = string.byte(data, 3) * 256 + string.byte(data, 4)
    local seq_num = string.byte(data, 5) * 16777216 +
                    string.byte(data, 6) * 65536 +
                    string.byte(data, 7) * 256 +
                    string.byte(data, 8)
    local ack_num = string.byte(data, 9) * 16777216 +
                    string.byte(data, 10) * 65536 +
                    string.byte(data, 11) * 256 +
                    string.byte(data, 12)
    local data_offset = bit32.rshift(string.byte(data, 13), 4) * 4
    local flags_byte = string.byte(data, 14)
    local window = string.byte(data, 15) * 256 + string.byte(data, 16)
    local checksum = string.byte(data, 17) * 256 + string.byte(data, 18)
    local urgent = string.byte(data, 19) * 256 + string.byte(data, 20)
    
    -- Decode flags
    local flags = {}
    for bit, name in pairs(M.tcp_flags) do
        if bit32.band(flags_byte, bit) ~= 0 then
            table.insert(flags, name)
        end
    end
    
    return {
        src_port = src_port,
        dst_port = dst_port,
        src_service = M.well_known_ports[src_port],
        dst_service = M.well_known_ports[dst_port],
        seq_number = seq_num,
        ack_number = ack_num,
        data_offset = data_offset,
        flags_raw = flags_byte,
        flags = flags,
        window_size = window,
        checksum = checksum,
        urgent_pointer = urgent,
        payload = data:sub(data_offset + 1)
    }
end

-- Decode UDP header
function M.decode_udp_header(data)
    if #data < 8 then return nil end
    
    local src_port = string.byte(data, 1) * 256 + string.byte(data, 2)
    local dst_port = string.byte(data, 3) * 256 + string.byte(data, 4)
    local length = string.byte(data, 5) * 256 + string.byte(data, 6)
    local checksum = string.byte(data, 7) * 256 + string.byte(data, 8)
    
    return {
        src_port = src_port,
        dst_port = dst_port,
        src_service = M.well_known_ports[src_port],
        dst_service = M.well_known_ports[dst_port],
        length = length,
        checksum = checksum,
        payload = data:sub(9)
    }
end

-- Decode ARP packet
function M.decode_arp(data)
    if #data < 28 then return nil end
    
    local htype = string.byte(data, 1) * 256 + string.byte(data, 2)
    local ptype = string.byte(data, 3) * 256 + string.byte(data, 4)
    local hlen = string.byte(data, 5)
    local plen = string.byte(data, 6)
    local oper = string.byte(data, 7) * 256 + string.byte(data, 8)
    
    local sha = data:sub(9, 14):gsub(".", function(c)
        return string.format("%02x:", string.byte(c))
    end):sub(1, -2)
    
    local spa = table.concat({
        string.byte(data, 15),
        string.byte(data, 16),
        string.byte(data, 17),
        string.byte(data, 18)
    }, ".")
    
    local tha = data:sub(19, 24):gsub(".", function(c)
        return string.format("%02x:", string.byte(c))
    end):sub(1, -2)
    
    local tpa = table.concat({
        string.byte(data, 25),
        string.byte(data, 26),
        string.byte(data, 27),
        string.byte(data, 28)
    }, ".")
    
    local op_names = {
        [1] = "REQUEST",
        [2] = "REPLY",
    }
    
    return {
        hardware_type = htype,
        protocol_type = ptype,
        hardware_len = hlen,
        protocol_len = plen,
        operation = oper,
        operation_name = op_names[oper] or "Unknown",
        sender_mac = sha,
        sender_ip = spa,
        target_mac = tha,
        target_ip = tpa
    }
end

-- Analyze packet statistics from /proc/net/dev
function M.analyze_interface_stats()
    local stats = {}
    
    local f = io.open("/proc/net/dev", "r")
    if f then
        -- Skip first two header lines
        f:read("*line")
        f:read("*line")
        
        for line in f:lines() do
            local iface, data = line:match("^%s*(%S+):%s*(.+)$")
            if iface and data then
                local numbers = {}
                for num in data:gmatch("%d+") do
                    table.insert(numbers, tonumber(num))
                end
                
                if #numbers >= 16 then
                    stats[iface] = {
                        rx_bytes = numbers[1],
                        rx_packets = numbers[2],
                        rx_errs = numbers[3],
                        rx_drop = numbers[4],
                        tx_bytes = numbers[9],
                        tx_packets = numbers[10],
                        tx_errs = numbers[11],
                        tx_drop = numbers[12]
                    }
                end
            end
        end
        f:close()
    end
    
    return stats
end

-- Get firewall/iptables rules summary
function M.get_firewall_rules()
    local rules = {}
    
    -- Try iptables
    local handle = io.popen("iptables -L -n --line-numbers 2>/dev/null | head -30 || echo 'iptables not available'")
    if handle then
        local output = handle:read("*all")
        handle:close()
        rules.iptables = output
    end
    
    -- Try nftables
    handle = io.popen("nft list ruleset 2>/dev/null | head -30 || echo 'nftables not available'")
    if handle then
        local output = handle:read("*all")
        handle:close()
        rules.nftables = output
    end
    
    return rules
end

return M
