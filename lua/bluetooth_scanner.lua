-- модуль сканирования bluetooth
-- обнаружение и анализ bluetooth устройств

local M = {}
M.version = "1.0"

-- известные oui (organizationally unique identifiers) для определения производителей
M.bluetooth_oui = {
    ["00:1A:7D"] = "Raspberry Pi",
    ["00:1B:10"] = "Intel",
    ["00:1C:B3"] = "Apple",
    ["00:1D:D9"] = "Nintendo",
    ["00:1E:3C"] = "Microsoft",
    ["00:1F:3A"] = "Sony",
    ["00:21:4C"] = "Samsung",
    ["00:23:D7"] = "Motorola",
    ["00:24:36"] = "Nokia",
    ["00:26:B4"] = "LG",
    ["00:37:6D"] = "Huawei",
    ["00:50:56"] = "VMware",
    ["00:90:4C"] = "Realtek",
    ["04:D6:AA"] = "Xiaomi",
    ["08:08:C2"] = "Sony",
    ["08:EC:A9"] = "Samsung",
    ["0C:FC:83"] = "Intel",
    ["10:AE:60"] = "OnePlus",
    ["14:F6:5A"] = "Apple",
    ["18:60:24"] = "Dell",
    ["18:AF:61"] = "Motorola",
    ["1C:1E:E3"] = "Samsung",
    ["1C:57:3E"] = "Huawei",
    ["20:16:B9"] = "LG",
    ["24:09:33"] = "Sony",
    ["24:4B:03"] = "Samsung",
    ["28:16:AD"] = "Motorola",
    ["28:56:5A"] = "Intel",
    ["2C:44:FD"] = "Huawei",
    ["30:19:66"] = "Microsoft",
    ["34:23:87"] = "LG",
    ["38:78:62"] = "Apple",
    ["3C:5A:37"] = "Google",
    ["3C:99:F7"] = "Liteon",
    ["40:20:5C"] = "Nintendo",
    ["40:9F:38"] = "Intel",
    ["44:00:10"] = "Motorola",
    ["44:37:E6"] = "Amazon",
    ["48:59:29"] = "Huawei",
    ["4C:7C:5F"] = "Xiaomi",
    ["50:01:BB"] = "Samsung",
    ["50:1A:C5"] = "Huawei",
    ["50:CC:F8"] = "Intel",
    ["54:60:09"] = "Google",
    ["58:48:22"] = "Apple",
    ["5C:0E:8B"] = "Motorola",
    ["5C:E8:EB"] = "Sony",
    ["60:45:CB"] = "Realtek",
    ["64:B5:4C"] = "Samsung",
    ["68:9A:87"] = "Liteon",
    ["70:48:F5"] = "Motorola",
    ["74:F0:6D"] = "Huawei",
    ["78:E1:03"] = "Nintendo",
    ["7C:F0:BA"] = "Intel",
    ["80:7A:BF"] = "Microsoft",
    ["84:73:03"] = "Huawei",
    ["88:28:3D"] = "Intel",
    ["8C:1A:BF"] = "Samsung",
    ["90:DD:5D"] = "OnePlus",
    ["94:3C:E9"] = "Huawei",
    ["98:01:A7"] = "Apple",
    ["9C:E6:35"] = "Huawei",
    ["A0:56:C2"] = "Intel",
    ["A4:C0:E1"] = "Samsung",
    ["A8:5C:27"] = "Apple",
    ["AC:22:0B"] = "Intel",
    ["AC:5F:3E"] = "Xiaomi",
    ["B0:AA:77"] = "Huawei",
    ["B4:29:3B"] = "Google",
    ["B8:27:EB"] = "Raspberry Pi",
    ["BC:83:85"] = "Huawei",
    ["C0:97:27"] = "Samsung",
    ["C4:93:D9"] = "Google",
    ["C8:A7:0A"] = "Apple",
    ["CC:FA:00"] = "Samsung",
    ["D0:49:8D"] = "Intel",
    ["D4:6B:A6"] = "Huawei",
    ["D8:30:62"] = "Google",
    ["DC:BF:E9"] = "Samsung",
    ["E0:0E:E1"] = "Huawei",
    ["E4:90:FD"] = "Intel",
    ["E8:2A:44"] = "Huawei",
    ["EC:08:6B"] = "Samsung",
    ["F0:27:2D"] = "Intel",
    ["F4:09:D8"] = "Samsung",
    ["F8:27:93"] = "Huawei",
    ["FC:19:99"] = "Realtek"
}

-- типы устройств по названию
M.device_types = {
    phone = {
        keywords = {"phone", "mobile", "android", "iphone", "samsung", "xiaomi", "huawei", "pixel", "oneplus"},
        icon = "phone"
    },
    audio = {
        keywords = {"headphone", "headset", "earbud", "speaker", "audio", "sound", "airpod", "pixel bud"},
        icon = "audio"
    },
    computer = {
        keywords = {"laptop", "desktop", "computer", "pc", "macbook", "imac", "surface"},
        icon = "computer"
    },
    wearable = {
        keywords = {"watch", "fitness", "band", "tracker", "smartwatch", "galaxy watch", "apple watch"},
        icon = "wearable"
    },
    peripheral = {
        keywords = {"keyboard", "mouse", "gamepad", "controller", "joystick"},
        icon = "peripheral"
    },
    car = {
        keywords = {"car", "auto", "vehicle", "toyota", "honda", "ford", "bmw", "audi"},
        icon = "car"
    },
    tv = {
        keywords = {"tv", "television", "chromecast", "fire tv", "roku", "smart tv"},
        icon = "tv"
    }
}

-- получение производителя по mac адресу
function M.get_vendor(mac)
    if not mac or #mac < 8 then return "unknown" end
    
    -- извлекаем oui (первые 3 байта)
    local oui = mac:sub(1, 8):upper()
    
    return M.bluetooth_oui[oui] or "unknown"
end

-- определение типа устройства по названию
function M.classify_device(name)
    if not name then return "unknown" end
    
    local lower_name = name:lower()
    
    for device_type, data in pairs(M.device_types) do
        for _, keyword in ipairs(data.keywords) do
            if lower_name:find(keyword) then
                return device_type
            end
        end
    end
    
    return "unknown"
end

-- сканирование bluetooth classic
function M.scan_classic(timeout)
    timeout = timeout or 10
    local devices = {}
    
    -- проверка наличия hcitool
    local check = io.popen("which hcitool 2>/dev/null")
    if not check or not check:read("*line") then
        return {error = "hcitool not found"}
    end
    check:close()
    
    -- включение адаптера
    os.execute("hciconfig hci0 up 2>/dev/null")
    
    -- сканирование
    local handle = io.popen("timeout " .. timeout .. " hcitool scan 2>/dev/null || echo ''")
    if handle then
        -- пропускаем заголовок
        handle:read("*line")
        
        for line in handle:lines() do
            local mac, name = line:match("^%s*([%x:]+)%s+(.+)$")
            if mac and name then
                local vendor = M.get_vendor(mac)
                local device_type = M.classify_device(name)
                
                table.insert(devices, {
                    mac = mac,
                    name = name,
                    vendor = vendor,
                    type = device_type,
                    bluetooth_version = "classic",
                    signal_strength = nil,
                    paired = false
                })
            end
        end
        handle:close()
    end
    
    return devices
end

-- сканирование bluetooth low energy
function M.scan_ble(timeout)
    timeout = timeout or 10
    local devices = {}
    
    -- используем bluetoothctl для ble
    local cmd = string.format(
        "timeout %d bluetoothctl scan on 2>/dev/null & sleep %d && bluetoothctl devices | head -30 || echo ''",
        timeout + 2, timeout
    )
    
    local handle = io.popen(cmd)
    if handle then
        for line in handle:lines() do
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
                    local vendor = M.get_vendor(mac)
                    local device_type = M.classify_device(name)
                    
                    table.insert(devices, {
                        mac = mac,
                        name = name or "unknown",
                        vendor = vendor,
                        type = device_type,
                        bluetooth_version = "BLE",
                        signal_strength = nil,
                        paired = false
                    })
                end
            end
        end
        handle:close()
    end
    
    return devices
end

-- получение спаренных устройств
function M.get_paired_devices()
    local paired = {}
    
    local handle = io.popen("bluetoothctl paired-devices 2>/dev/null || echo ''")
    if handle then
        for line in handle:lines() do
            local mac, name = line:match("Device%s+([%x:]+)%s+(.+)$")
            if mac then
                local vendor = M.get_vendor(mac)
                table.insert(paired, {
                    mac = mac,
                    name = name or "unknown",
                    vendor = vendor,
                    paired = true,
                    connected = false -- будет обновлено позже
                })
            end
        end
        handle:close()
    end
    
    return paired
end

-- проверка подключенных устройств
function M.get_connected_devices()
    local connected = {}
    
    local handle = io.popen("bluetoothctl info 2>/dev/null | grep -E '(Device|Connected)' || echo ''")
    if handle then
        local current_mac = nil
        for line in handle:lines() do
            local mac = line:match("Device%s+([%x:]+)")
            if mac then
                current_mac = mac
            end
            
            if line:find("Connected: yes") and current_mac then
                table.insert(connected, current_mac)
            end
        end
        handle:close()
    end
    
    return connected
end

-- полное сканирование bluetooth
function M.full_scan(timeout)
    timeout = timeout or 15
    
    -- объединяем classic и ble
    local classic_devices = M.scan_classic(timeout)
    local ble_devices = M.scan_ble(timeout)
    local paired = M.get_paired_devices()
    
    -- объединяем и убираем дубликаты
    local all_devices = {}
    local seen = {}
    
    -- добавляем спаренные устройства
    for _, dev in ipairs(paired) do
        seen[dev.mac] = true
        dev.source = "paired"
        table.insert(all_devices, dev)
    end
    
    -- добавляем classic устройства
    for _, dev in ipairs(classic_devices) do
        if not seen[dev.mac] then
            seen[dev.mac] = true
            dev.source = "scan"
            table.insert(all_devices, dev)
        end
    end
    
    -- добавляем ble устройства
    for _, dev in ipairs(ble_devices) do
        if not seen[dev.mac] then
            seen[dev.mac] = true
            dev.source = "ble_scan"
            table.insert(all_devices, dev)
        end
    end
    
    -- проверяем какие подключены
    local connected = M.get_connected_devices()
    local connected_map = {}
    for _, mac in ipairs(connected) do
        connected_map[mac] = true
    end
    
    for _, dev in ipairs(all_devices) do
        dev.connected = connected_map[dev.mac] or false
    end
    
    return {
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
        devices = all_devices,
        count = #all_devices,
        connected_count = #connected,
        paired_count = #paired
    }
end

-- анализ найденных устройств
function M.analyze_devices(devices)
    local analysis = {
        by_type = {},
        by_vendor = {},
        phones_nearby = 0,
        audio_nearby = 0,
        computers_nearby = 0,
        wearables_nearby = 0,
        unknown = 0,
        recommendations = {}
    }
    
    for _, dev in ipairs(devices) do
        -- по типу
        local dtype = dev.type or "unknown"
        analysis.by_type[dtype] = (analysis.by_type[dtype] or 0) + 1
        
        -- по производителю
        local vendor = dev.vendor or "unknown"
        analysis.by_vendor[vendor] = (analysis.by_vendor[vendor] or 0) + 1
        
        -- счетчики
        if dtype == "phone" then
            analysis.phones_nearby = analysis.phones_nearby + 1
        elseif dtype == "audio" then
            analysis.audio_nearby = analysis.audio_nearby + 1
        elseif dtype == "computer" then
            analysis.computers_nearby = analysis.computers_nearby + 1
        elseif dtype == "wearable" then
            analysis.wearables_nearby = analysis.wearables_nearby + 1
        else
            analysis.unknown = analysis.unknown + 1
        end
    end
    
    -- рекомендации
    if analysis.phones_nearby > 3 then
        table.insert(analysis.recommendations, "обнаружено много телефонов - возможно публичное место")
    end
    
    if analysis.unknown > 5 then
        table.insert(analysis.recommendations, "много устройств с неопределенным типом")
    end
    
    return analysis
end

-- вывод отчета
function M.print_report(scan_result)
    print("=" .. string.rep("-", 60))
    print("отчет bluetooth сканирования")
    print("=" .. string.rep("-", 60))
    print("время: " .. scan_result.timestamp)
    print("найдено устройств: " .. scan_result.count)
    print("подключено: " .. scan_result.connected_count)
    print("спарено в системе: " .. scan_result.paired_count)
    print()
    
    -- анализ
    local analysis = M.analyze_devices(scan_result.devices)
    
    print("по типам:")
    for dtype, count in pairs(analysis.by_type) do
        print("  " .. dtype .. ": " .. count)
    end
    print()
    
    print("список устройств:")
    for i, dev in ipairs(scan_result.devices) do
        local status = ""
        if dev.connected then
            status = " [connected]"
        elseif dev.paired then
            status = " [paired]"
        end
        
        print(string.format("  %d. %s (%s)%s", i, dev.name, dev.mac, status))
        print(string.format("     vendor: %s | type: %s | bt: %s", 
            dev.vendor, dev.type, dev.bluetooth_version))
    end
    
    if #analysis.recommendations > 0 then
        print()
        print("примечания:")
        for _, rec in ipairs(analysis.recommendations) do
            print("  * " .. rec)
        end
    end
    
    print("=" .. string.rep("-", 60))
end

return M
