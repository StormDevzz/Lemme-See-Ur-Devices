-- модуль мониторинга системы
-- сбор метрик процессора, памяти, дисков и сети

local M = {}
M.version = "1.0"

-- история метрик (кольцевой буфер)
M.history = {}
M.max_history = 100

-- получение загрузки cpu
function M.get_cpu_usage()
    local usage = {}
    
    local f = io.open("/proc/stat", "r")
    if not f then return nil end
    
    -- первая строка - агрегированная статистика
    local line = f:read("*line")
    f:close()
    
    if not line then return nil end
    
    -- cpu user nice system idle iowait irq softirq steal guest guest_nice
    local fields = {}
    for field in line:gmatch("%S+") do
        table.insert(fields, field)
    end
    
    if #fields < 5 then return nil end
    
    local user = tonumber(fields[2]) or 0
    local nice = tonumber(fields[3]) or 0
    local system = tonumber(fields[4]) or 0
    local idle = tonumber(fields[5]) or 0
    local iowait = tonumber(fields[6]) or 0
    local irq = tonumber(fields[7]) or 0
    local softirq = tonumber(fields[8]) or 0
    
    local total = user + nice + system + idle + iowait + irq + softirq
    local used = user + nice + system + irq + softirq
    
    if total > 0 then
        usage.total = total
        usage.used = used
        usage.idle = idle
        usage.percent = math.floor((used / total) * 100)
        usage.user = user
        usage.system = system
        usage.iowait = iowait
    end
    
    return usage
end

-- получение информации о памяти
function M.get_memory_info()
    local mem = {}
    
    local f = io.open("/proc/meminfo", "r")
    if not f then return nil end
    
    for line in f:lines() do
        local key, value = line:match("^([^:]+):%s*(%d+)")
        if key and value then
            -- конвертируем в мб
            mem[key] = math.floor(tonumber(value) / 1024)
        end
    end
    f:close()
    
    -- вычисляем использование
    if mem.MemTotal and mem.MemAvailable then
        mem.used = mem.MemTotal - mem.MemAvailable
        mem.percent = math.floor((mem.used / mem.MemTotal) * 100)
    end
    
    return mem
end

-- получение информации о swap
function M.get_swap_info()
    local swap = {}
    
    local f = io.open("/proc/swaps", "r")
    if not f then return nil end
    
    -- пропускаем заголовок
    f:read("*line")
    
    local total = 0
    local used = 0
    
    for line in f:lines() do
        local parts = {}
        for part in line:gmatch("%S+") do
            table.insert(parts, part)
        end
        
        if #parts >= 4 then
            total = total + tonumber(parts[3])
            used = used + tonumber(parts[4])
        end
    end
    f:close()
    
    swap.total_mb = math.floor(total / 1024)
    swap.used_mb = math.floor(used / 1024)
    swap.free_mb = swap.total_mb - swap.used_mb
    
    if swap.total_mb > 0 then
        swap.percent = math.floor((swap.used_mb / swap.total_mb) * 100)
    else
        swap.percent = 0
    end
    
    return swap
end

-- получение информации о дисках
function M.get_disk_info()
    local disks = {}
    
    -- читаем mounts
    local f = io.open("/proc/mounts", "r")
    if not f then return nil end
    
    for line in f:lines() do
        local device, mount, fs = line:match("^(%S+)%s+(%S+)%s+(%S+)")
        
        -- пропускаем виртуальные файловые системы
        if device and device:find("^/dev/") then
            -- игнорируем loop и tmpfs
            if not device:find("loop") and fs ~= "tmpfs" and fs ~= "devtmpfs" then
                local disk = {
                    device = device,
                    mount = mount,
                    filesystem = fs,
                    total = nil,
                    used = nil,
                    free = nil,
                    percent = nil
                }
                
                -- получаем размер через df
                local cmd = "df -m " .. mount .. " 2>/dev/null | tail -1"
                local handle = io.popen(cmd)
                if handle then
                    local df_line = handle:read("*line")
                    handle:close()
                    
                    if df_line then
                        local parts = {}
                        for part in df_line:gmatch("%S+") do
                            table.insert(parts, part)
                        end
                        
                        if #parts >= 6 then
                            disk.total = tonumber(parts[2])
                            disk.used = tonumber(parts[3])
                            disk.free = tonumber(parts[4])
                            disk.percent = tonumber(parts[5]:gsub("%%", ""))
                        end
                    end
                end
                
                table.insert(disks, disk)
            end
        end
    end
    f:close()
    
    return disks
end

-- получение сетевой статистики
function M.get_network_stats()
    local stats = {}
    
    local f = io.open("/proc/net/dev", "r")
    if not f then return nil end
    
    -- пропускаем 2 заголовка
    f:read("*line")
    f:read("*line")
    
    for line in f:lines() do
        local iface, rx_bytes, rx_packets, rx_errs, rx_drop, _, _, _, _, 
              tx_bytes, tx_packets, tx_errs, tx_drop = line:match(
            "^%s*(%S+):%s*(%d+)%s*(%d+)%s*(%d+)%s*(%d+)%s*%d+%s*%d+%s*%d+%s*%d+%s*(%d+)%s*(%d+)%s*(%d+)%s*(%d+)"
        )
        
        if iface and iface ~= "lo:" then
            iface = iface:gsub(":", "")
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

-- получение uptime
function M.get_uptime()
    local f = io.open("/proc/uptime", "r")
    if not f then return nil end
    
    local uptime_str = f:read("*line")
    f:close()
    
    if uptime_str then
        local uptime_sec = tonumber(uptime_str:match("^(%S+)"))
        return uptime_sec
    end
    
    return nil
end

-- получение load average
function M.get_loadavg()
    local f = io.open("/proc/loadavg", "r")
    if not f then return nil end
    
    local line = f:read("*line")
    f:close()
    
    if line then
        local one, five, fifteen = line:match("^(%S+)%s+(%S+)%s+(%S+)")
        return {
            one = tonumber(one),
            five = tonumber(five),
            fifteen = tonumber(fifteen)
        }
    end
    
    return nil
end

-- получение температуры
function M.get_temperatures()
    local temps = {}
    
    -- ищем в thermal zones
    local thermal_path = "/sys/class/thermal"
    local handle = io.popen("ls " .. thermal_path .. " 2>/dev/null")
    
    if handle then
        for zone in handle:lines() do
            if zone:find("thermal_zone") then
                local temp_file = thermal_path .. "/" .. zone .. "/temp"
                local f = io.open(temp_file, "r")
                if f then
                    local temp = f:read("*line")
                    f:close()
                    
                    -- получаем тип
                    local type_file = thermal_path .. "/" .. zone .. "/type"
                    local t = io.open(type_file, "r")
                    local zone_type = "unknown"
                    if t then
                        zone_type = t:read("*line") or "unknown"
                        t:close()
                    end
                    
                    if temp then
                        table.insert(temps, {
                            zone = zone,
                            type = zone_type,
                            temp_c = math.floor(tonumber(temp) / 1000)
                        })
                    end
                end
            end
        end
        handle:close()
    end
    
    -- ищем в hwmon
    local hwmon_path = "/sys/class/hwmon"
    local hwmon_handle = io.popen("ls " .. hwmon_path .. " 2>/dev/null")
    
    if hwmon_handle then
        for hwmon in hwmon_handle:lines() do
            if hwmon:find("hwmon") then
                local name_file = hwmon_path .. "/" .. hwmon .. "/name"
                local n = io.open(name_file, "r")
                local chip_name = "unknown"
                if n then
                    chip_name = n:read("*line") or "unknown"
                    n:close()
                end
                
                -- ищем температурные датчики
                local temp_handle = io.popen("ls " .. hwmon_path .. "/" .. hwmon .. " 2>/dev/null | grep temp")
                if temp_handle then
                    for temp_input in temp_handle:lines() do
                        if temp_input:find("_input$") then
                            local f = io.open(hwmon_path .. "/" .. hwmon .. "/" .. temp_input, "r")
                            if f then
                                local val = f:read("*line")
                                f:close()
                                
                                if val then
                                    local label_file = temp_input:gsub("_input", "_label")
                                    local l = io.open(hwmon_path .. "/" .. hwmon .. "/" .. label_file, "r")
                                    local label = chip_name
                                    if l then
                                        local lval = l:read("*line")
                                        if lval then
                                            label = chip_name .. " - " .. lval
                                        end
                                        l:close()
                                    end
                                    
                                    table.insert(temps, {
                                        zone = hwmon .. "/" .. temp_input,
                                        type = label,
                                        temp_c = math.floor(tonumber(val) / 1000)
                                    })
                                end
                            end
                        end
                    end
                    temp_handle:close()
                end
            end
        end
        hwmon_handle:close()
    end
    
    return temps
end

-- получение количества процессов
function M.get_process_count()
    local count = 0
    local handle = io.popen("ls /proc 2>/dev/null | grep '^[0-9]' | wc -l")
    if handle then
        local result = handle:read("*line")
        handle:close()
        count = tonumber(result) or 0
    end
    return count
end

-- снимок всей системы
function M.get_system_snapshot()
    local snapshot = {
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
        cpu = M.get_cpu_usage(),
        memory = M.get_memory_info(),
        swap = M.get_swap_info(),
        disks = M.get_disk_info(),
        network = M.get_network_stats(),
        loadavg = M.get_loadavg(),
        uptime = M.get_uptime(),
        temperatures = M.get_temperatures(),
        processes = M.get_process_count()
    }
    
    -- сохраняем в историю
    table.insert(M.history, snapshot)
    if #M.history > M.max_history then
        table.remove(M.history, 1)
    end
    
    return snapshot
end

-- проверка алертов
function M.check_alerts(snapshot)
    local alerts = {}
    
    -- высокая загрузка cpu
    if snapshot.cpu and snapshot.cpu.percent > 80 then
        table.insert(alerts, {
            level = "warning",
            component = "cpu",
            message = "высокая загрузка cpu: " .. snapshot.cpu.percent .. "%",
            threshold = 80
        })
    end
    
    -- высокое использование памяти
    if snapshot.memory and snapshot.memory.percent then
        if snapshot.memory.percent > 90 then
            table.insert(alerts, {
                level = "critical",
                component = "memory",
                message = "критическое использование памяти: " .. snapshot.memory.percent .. "%",
                threshold = 90
            })
        elseif snapshot.memory.percent > 80 then
            table.insert(alerts, {
                level = "warning",
                component = "memory",
                message = "высокое использование памяти: " .. snapshot.memory.percent .. "%",
                threshold = 80
            })
        end
    end
    
    -- заполненность дисков
    if snapshot.disks then
        for _, disk in ipairs(snapshot.disks) do
            if disk.percent and disk.percent > 90 then
                table.insert(alerts, {
                    level = "warning",
                    component = "disk_" .. disk.device,
                    message = "диск " .. disk.mount .. " заполнен на " .. disk.percent .. "%",
                    threshold = 90
                })
            end
        end
    end
    
    -- температура
    if snapshot.temperatures then
        for _, temp in ipairs(snapshot.temperatures) do
            if temp.temp_c > 80 then
                table.insert(alerts, {
                    level = "warning",
                    component = "temperature",
                    message = temp.type .. ": " .. temp.temp_c .. "C",
                    threshold = 80
                })
            end
        end
    end
    
    -- высокая нагрузка
    if snapshot.loadavg and snapshot.loadavg.one > 4 then
        table.insert(alerts, {
            level = "warning",
            component = "load",
            message = "высокая нагрузка: " .. snapshot.loadavg.one,
            threshold = 4
        })
    end
    
    return alerts
end

-- вывод отчета
function M.print_report(snapshot)
    print("=" .. string.rep("-", 60))
    print("отчет мониторинга системы")
    print("=" .. string.rep("-", 60))
    print("время: " .. snapshot.timestamp)
    print()
    
    -- cpu
    if snapshot.cpu then
        print("[cpu]")
        print("  загрузка: " .. snapshot.cpu.percent .. "%")
        print("  user: " .. snapshot.cpu.user .. " | system: " .. snapshot.cpu.system)
        print()
    end
    
    -- память
    if snapshot.memory then
        print("[память]")
        print("  всего: " .. (snapshot.memory.MemTotal or "?") .. " mb")
        print("  использовано: " .. (snapshot.memory.used or "?") .. " mb (" .. (snapshot.memory.percent or "?") .. "%)")
        print("  available: " .. (snapshot.memory.MemAvailable or "?") .. " mb")
        print()
    end
    
    -- swap
    if snapshot.swap then
        print("[swap]")
        print("  использовано: " .. snapshot.swap.used_mb .. "/" .. snapshot.swap.total_mb .. " mb")
        print()
    end
    
    -- диски
    if snapshot.disks then
        print("[диски]")
        for _, disk in ipairs(snapshot.disks) do
            local used_bar = ""
            if disk.percent then
                local filled = math.floor(disk.percent / 5)
                used_bar = "[" .. string.rep("#", filled) .. string.rep("-", 20 - filled) .. "]"
            end
            print(string.format("  %s: %s %s%% %s",
                disk.device,
                disk.mount,
                disk.percent or "?",
                used_bar))
        end
        print()
    end
    
    -- сеть
    if snapshot.network and #snapshot.network > 0 then
        print("[сеть]")
        for _, net in ipairs(snapshot.network) do
            local rx_mb = math.floor(net.rx_bytes / (1024 * 1024))
            local tx_mb = math.floor(net.tx_bytes / (1024 * 1024))
            print(string.format("  %s: rx %d mb (%d errs), tx %d mb (%d errs)",
                net.interface,
                rx_mb,
                net.rx_errors,
                tx_mb,
                net.tx_errors))
        end
        print()
    end
    
    -- температура
    if snapshot.temperatures and #snapshot.temperatures > 0 then
        print("[температура]")
        for _, temp in ipairs(snapshot.temperatures) do
            local mark = ""
            if temp.temp_c > 70 then
                mark = " [!]"
            elseif temp.temp_c > 60 then
                mark = " [*]"
            end
            print(string.format("  %s: %dC%s", temp.type, temp.temp_c, mark))
        end
        print()
    end
    
    -- нагрузка и uptime
    if snapshot.loadavg then
        print("[нагрузка] " .. snapshot.loadavg.one .. ", " .. snapshot.loadavg.five .. ", " .. snapshot.loadavg.fifteen)
    end
    
    if snapshot.uptime then
        local hours = math.floor(snapshot.uptime / 3600)
        local mins = math.floor((snapshot.uptime % 3600) / 60)
        print("[uptime] " .. hours .. "ч " .. mins .. "м")
    end
    
    print("[процессов] " .. snapshot.processes)
    print()
    
    -- алерты
    local alerts = M.check_alerts(snapshot)
    if #alerts > 0 then
        print("[!] предупреждения:")
        for _, alert in ipairs(alerts) do
            local mark = alert.level == "critical" and "[X]" or "[!]"
            print("  " .. mark .. " " .. alert.message)
        end
        print()
    end
    
    print("=" .. string.rep("-", 60))
end

-- экспорт в json
function M.export_json(filename, snapshots)
    filename = filename or "system_metrics.json"
    snapshots = snapshots or M.history
    
    local f = io.open(filename, "w")
    if not f then return nil end
    
    f:write("[\n")
    for i, snap in ipairs(snapshots) do
        f:write("  {\n")
        f:write('    "timestamp": "' .. (snap.timestamp or "") .. '",\n')
        
        if snap.cpu then
            f:write('    "cpu_percent": ' .. (snap.cpu.percent or 0) .. ',\n')
        end
        
        if snap.memory then
            f:write('    "memory_percent": ' .. (snap.memory.percent or 0) .. ',\n')
            f:write('    "memory_used_mb": ' .. (snap.memory.used or 0) .. ',\n')
        end
        
        f:write('    "processes": ' .. (snap.processes or 0) .. '\n')
        f:write("  }")
        if i < #snapshots then
            f:write(",")
        end
        f:write("\n")
    end
    f:write("]\n")
    f:close()
    
    return filename
end

return M
