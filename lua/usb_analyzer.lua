-- модуль анализа usb устройств
-- расширенный анализ и классификация usb устройств

local M = {}
M.version = "1.0"

-- база vid/pid производителей
M.vendors = {
    ["046d"] = "Logitech",
    ["04e8"] = "Samsung",
    ["05ac"] = "Apple",
    ["0781"] = "SanDisk",
    ["0951"] = "Kingston",
    ["0bda"] = "Realtek",
    ["0c45"] = "Microdia",
    ["13fe"] = "Phison",
    ["18d1"] = "Google",
    ["1c6b"] = "Phison",
    ["2516"] = "Cooler Master",
    ["29ea"] = "KWorld",
    ["413c"] = "Dell",
    ["8086"] = "Intel",
    ["090c"] = "Feiya",
    ["1058"] = "Western Digital",
    ["058f"] = "Alcor Micro",
    ["0480"] = "Toshiba",
    ["040b"] = "Weltrend",
    ["045e"] = "Microsoft",
    ["0461"] = "Primax",
    ["0463"] = "MGE UPS",
    ["046a"] = "Cherry",
    ["046b"] = "APC",
    ["046c"] = "Saitek",
    ["0471"] = "Philips",
    ["047d"] = "Kensington",
    ["04a9"] = "Canon",
    ["04b8"] = "Seiko Epson",
    ["04b9"] = "Samsung",
    ["04c5"] = "Fujitsu",
    ["04d8"] = "Future Technology",
    ["04d9"] = "Holtek",
    ["04da"] = "Panasonic",
    ["04e6"] = "SCM Microsystems",
    ["04e7"] = "Elo Touch",
    ["04ea"] = "Brother",
    ["04f2"] = "Chicony",
    ["04f3"] = "Elan",
    ["050d"] = "Belkin",
    ["0510"] = "Sejin",
    ["0518"] = "C-Media",
    ["051d"] = "National Semi",
    ["0529"] = "Aladdin",
    ["052b"] = "Moschip",
    ["054c"] = "Sony",
    ["0550"] = "Prolific",
    ["0584"] = "Raritan",
    ["0590"] = "Omron",
    ["059b"] = "Iomega",
    ["05a4"] = "Ortek",
    ["05a9"] = "OmniVision",
    ["05ac"] = "Apple",
    ["05bc"] = "Canon",
    ["05c6"] = "Qualcomm",
    ["05dc"] = "Lexmark",
    ["05e0"] = "Symbol",
    ["05e1"] = "HanfTek",
    ["05e3"] = "Genesys",
    ["05f3"] = "PI Engineering",
    ["05fe"] = "Chic",
    ["0603"] = "Novatek",
    ["060b"] = "Solid Year",
    ["0611"] = "Zeal",
    ["0613"] = "Plantronics",
    ["061c"] = "Institut",
    ["061d"] = "BAE",
    ["0624"] = "Microchip",
    ["0627"] = "ADC",
    ["062a"] = "MosArt",
    ["0638"] = "Strobe",
    ["0639"] = "OmniKey",
    ["0644"] = "TEAC",
    ["064e"] = "SUYIN",
    ["0658"] = "SigmaTel",
    ["065a"] = "Nokia",
    ["065e"] = "Sony",
    ["0665"] = "Nocon",
    ["0675"] = "D-Link",
    ["0676"] = "Adomax",
    ["067b"] = "Prolific",
    ["067c"] = "Ihr",
    ["067e"] = "Intermec",
    ["0681"] = "Siemens",
    ["0682"] = "Fargo",
    ["0686"] = "Minolta",
    ["068a"] = "Pace",
    ["068e"] = "CH Products",
    ["0693"] = "Hewlett Packard",
    ["0694"] = "Hewlett Packard",
    ["0698"] = "CH Products",
    ["069a"] = "Asuscom",
    ["069b"] = "Hewlett Packard",
    ["069d"] = "Hughes",
    ["06a2"] = "Topaz",
    ["06a3"] = "Saitek",
    ["06a4"] = "Xiamen",
    ["06a5"] = "Divio",
    ["06a8"] = "Topaz",
    ["06ac"] = "Fujitsu",
    ["06ad"] = "Harting",
    ["06b8"] = "Pixela",
    ["06b9"] = "Alcatel",
    ["06bc"] = "Oppo",
    ["06be"] = "BenQ",
    ["06bf"] = "Leoco",
    ["06c2"] = "Phidgets",
    ["06c4"] = "Axalto",
    ["06c6"] = "Fomax",
    ["06ca"] = "Guillemot",
    ["06cb"] = "Synaptics",
    ["06cc"] = "Terayon",
    ["06d3"] = "Mitsumi",
    ["06d4"] = "DSP",
    ["06d6"] = "Alcor",
    ["06d8"] = "Shanghai",
    ["06dc"] = "Hughes",
    ["06e0"] = "NovaTech",
    ["06e1"] = "ADS",
    ["06e6"] = "Transmonde",
    ["06ea"] = "Toshiba",
    ["06eb"] = "Emagix",
    ["06f8"] = "Hengstler",
    ["06fa"] = "Hama",
    ["06fd"] = "Newnex",
    ["0701"] = "Hypercom",
    ["0703"] = "Bay",
    ["0707"] = "Beko",
    ["0708"] = "Cross",
    ["0709"] = "Svoa",
    ["070a"] = "Gretag",
    ["070d"] = "Hewlett Packard",
    ["0711"] = "SIIG",
    ["0713"] = "Xatel",
    ["0717"] = "MicroStore",
    ["0718"] = "SanDisk",
    ["0719"] = "Oryx",
    ["071b"] = "Rockwell",
    ["0723"] = "Susteen",
    ["0726"] = "Vanguard",
    ["0729"] = "Sunix",
    ["072f"] = "Spansion",
    ["0734"] = "Softing",
    ["0735"] = "Shenzhen",
    ["0736"] = "Hospira",
    ["0738"] = "Chrontel",
    ["073b"] = "Kodak",
    ["073e"] = "Nihon",
    ["0742"] = "Stargate",
    ["0743"] = "Mutron",
    ["0745"] = "Sinton",
    ["0746"] = "Kobian",
    ["0747"] = "Netac",
    ["0748"] = "Kyocera",
    ["0749"] = "Syntek",
    ["074a"] = "Foxconn",
    ["074d"] = "Micronas",
    ["074e"] = "Staples",
    ["0755"] = "Intelligent",
    ["0757"] = "Cisco",
    ["075b"] = "Sophos",
    ["0763"] = "M-Audio",
    ["0764"] = "CyberPower",
    ["0765"] = "X-Rite",
    ["0766"] = "Toshiba",
    ["0767"] = "Toshiba",
    ["0768"] = "Techwin",
    ["0769"] = "Imation",
    ["076a"] = "Ingenico",
    ["076b"] = "OmniKey",
    ["076c"] = "D-Link",
    ["076d"] = "Sagem",
    ["076e"] = "Toshiba",
    ["0770"] = "Honeywell",
    ["0771"] = "Nihon",
    ["0772"] = "Royaltek",
    ["0774"] = "SanDisk",
    ["0775"] = "Palo",
    ["0776"] = "Spinnaker",
    ["0777"] = "Wavecom",
    ["0778"] = "Toshiba",
    ["0779"] = "Sankyo",
    ["077a"] = "Sankyo",
    ["077b"] = "Intel",
    ["077c"] = "Toshiba",
    ["077d"] = "Sankyo",
    ["077f"] = "Wellco",
    ["0780"] = "Nagano",
    ["0781"] = "SanDisk",
    ["0782"] = "Toshiba",
    ["0783"] = "C3PO",
    ["0784"] = "Eutron",
    ["0785"] = "Sagem",
    ["0786"] = "Fujitsu",
    ["0789"] = "Logitec",
    ["078b"] = "Hewlett Packard",
    ["078c"] = "Gigatech",
    ["078d"] = "VTech",
    ["0791"] = "Acer",
    ["0792"] = "GaMi",
    ["0793"] = "Cirque",
    ["0794"] = "Aladdin",
    ["0795"] = "WEP",
    ["0796"] = "Toshiba",
    ["0797"] = "Nokia",
    ["0798"] = "Nokia",
    ["0799"] = "Toshiba",
    ["079a"] = "Nokia",
    ["079b"] = "Toshiba",
    ["079c"] = "Toshiba",
    ["079d"] = "Nokia",
    ["079e"] = "Toshiba",
    ["079f"] = "Nokia",
    ["07a0"] = "Toshiba",
    ["07a1"] = "Nokia",
    ["07a2"] = "Toshiba",
    ["07a3"] = "Nokia",
    ["07a4"] = "Toshiba",
    ["07a5"] = "Nokia",
    ["07a6"] = "Toshiba",
    ["07a7"] = "Nokia",
    ["07a8"] = "Toshiba",
    ["07a9"] = "Nokia",
    ["07aa"] = "Toshiba",
    ["07ab"] = "Nokia",
    ["07ac"] = "Toshiba",
    ["07ad"] = "Nokia",
    ["07ae"] = "Toshiba",
    ["07af"] = "Nokia",
    ["07b0"] = "Toshiba",
    ["07b1"] = "Nokia",
    ["07b2"] = "Toshiba",
    ["07b3"] = "Nokia",
    ["07b4"] = "Toshiba",
    ["07b5"] = "Nokia",
    ["07b6"] = "Toshiba",
    ["07b7"] = "Nokia",
    ["07b8"] = "Toshiba",
    ["07b9"] = "Nokia",
    ["07ba"] = "Toshiba",
    ["07bb"] = "Nokia",
    ["07bc"] = "Toshiba",
    ["07bd"] = "Nokia",
    ["07be"] = "Toshiba",
    ["07bf"] = "Nokia",
    ["07c0"] = "Toshiba",
    ["07c1"] = "Nokia",
    ["07c2"] = "Toshiba",
    ["07c3"] = "Nokia",
    ["07c4"] = "Toshiba",
    ["07c5"] = "Nokia",
    ["07c6"] = "Toshiba",
    ["07c7"] = "Nokia",
    ["07c8"] = "Toshiba",
    ["07c9"] = "Nokia",
    ["07ca"] = "Toshiba",
    ["07cb"] = "Nokia",
    ["07cc"] = "Toshiba",
    ["07cd"] = "Nokia",
    ["07ce"] = "Toshiba",
    ["07cf"] = "Nokia",
    ["07d0"] = "Toshiba",
    ["07d1"] = "Nokia",
    ["07d2"] = "Toshiba",
    ["07d3"] = "Nokia",
    ["07d4"] = "Toshiba",
    ["07d5"] = "Nokia",
    ["07d6"] = "Toshiba",
    ["07d7"] = "Nokia",
    ["07d8"] = "Toshiba",
    ["07d9"] = "Nokia",
    ["07da"] = "Toshiba",
    ["07db"] = "Nokia",
    ["07dc"] = "Toshiba",
    ["07dd"] = "Nokia",
    ["07de"] = "Toshiba",
    ["07df"] = "Nokia",
    ["07e0"] = "Toshiba",
    ["07e1"] = "Nokia",
    ["07e2"] = "Toshiba",
    ["07e3"] = "Nokia",
    ["07e4"] = "Toshiba",
    ["07e5"] = "Nokia",
    ["07e6"] = "Toshiba",
    ["07e7"] = "Nokia",
    ["07e8"] = "Toshiba",
    ["07e9"] = "Nokia",
    ["07ea"] = "Toshiba",
    ["07eb"] = "Nokia",
    ["07ec"] = "Toshiba",
    ["07ed"] = "Nokia",
    ["07ee"] = "Toshiba",
    ["07ef"] = "Nokia",
    ["07f0"] = "Toshiba",
    ["07f1"] = "Nokia",
    ["07f2"] = "Toshiba",
    ["07f3"] = "Nokia",
    ["07f4"] = "Toshiba",
    ["07f5"] = "Nokia",
    ["07f6"] = "Toshiba",
    ["07f7"] = "Nokia",
    ["07f8"] = "Toshiba",
    ["07f9"] = "Nokia",
    ["07fa"] = "Toshiba",
    ["07fb"] = "Nokia",
    ["07fc"] = "Toshiba",
    ["07fd"] = "Nokia",
    ["07fe"] = "Toshiba",
    ["07ff"] = "Nokia"
}

-- классы usb устройств
M.device_classes = {
    [0x00] = "use interface descriptor",
    [0x01] = "audio",
    [0x02] = "communications",
    [0x03] = "hid",
    [0x05] = "physical",
    [0x06] = "image",
    [0x07] = "printer",
    [0x08] = "mass storage",
    [0x09] = "hub",
    [0x0a] = "cdc-data",
    [0x0b] = "smart card",
    [0x0d] = "content security",
    [0x0e] = "video",
    [0x0f] = "personal healthcare",
    [0x10] = "audio/video",
    [0x11] = "billboard",
    [0x12] = "usb type-c bridge",
    [0xdc] = "diagnostic device",
    [0xe0] = "wireless controller",
    [0xef] = "miscellaneous",
    [0xfe] = "application specific",
    [0xff] = "vendor specific"
}

-- подклассы mass storage
M.storage_subclasses = {
    [0x00] = "scsi",
    [0x01] = "rbc",
    [0x02] = "atapi",
    [0x03] = "qic157",
    [0x04] = "ufi",
    [0x05] = "obsolete",
    [0x06] = "scsi transparent",
    [0x07] = "lmc",
    [0x08] = "ieee1667"
}

-- протоколы mass storage
M.storage_protocols = {
    [0x00] = "cbi with command completion interrupt",
    [0x01] = "cbi without command completion interrupt",
    [0x02] = "obsolete",
    [0x50] = "bulk-only",
    [0x62] = "ata"
}

-- получение производителя по vid
function M.get_vendor(vid)
    if not vid then return "unknown" end
    vid = vid:lower()
    return M.vendors[vid] or "unknown"
end

-- получение класса устройства
function M.get_device_class(class_code)
    local code = tonumber(class_code, 16)
    if not code then return "unknown" end
    return M.device_classes[code] or "unknown"
end

-- парсинг usb устройств из sysfs
function M.parse_usb_devices()
    local devices = {}
    local usb_path = "/sys/bus/usb/devices"
    
    -- проверяем существование
    local test = io.open(usb_path, "r")
    if not test then
        return {error = "sysfs not available"}
    end
    test:close()
    
    -- получаем список устройств
    local handle = io.popen("ls " .. usb_path .. " 2>/dev/null")
    if not handle then
        return {error = "cannot list usb devices"}
    end
    
    for dev_name in handle:lines() do
        -- пропускаем hub и корневые устройства без номера
        if dev_name:match("^%d") then
            local dev_path = usb_path .. "/" .. dev_name
            
            local device = {
                sys_path = dev_path,
                busnum = nil,
                devnum = nil,
                idVendor = nil,
                idProduct = nil,
                manufacturer = nil,
                product = nil,
                serial = nil,
                bDeviceClass = nil,
                bDeviceSubClass = nil,
                bDeviceProtocol = nil,
                speed = nil,
                bConfigurationValue = nil,
                bMaxPower = nil
            }
            
            -- чтение всех файлов
            local files = {
                "busnum", "devnum", "idVendor", "idProduct",
                "manufacturer", "product", "serial",
                "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol",
                "speed", "bConfigurationValue", "bMaxPower"
            }
            
            for _, fname in ipairs(files) do
                local f = io.open(dev_path .. "/" .. fname, "r")
                if f then
                    local val = f:read("*line")
                    f:close()
                    if val then
                        device[fname] = val:gsub("^%s*", ""):gsub("%s*$", "")
                    end
                end
            end
            
            -- дополнительная информация
            if device.idVendor then
                device.vendor_name = M.get_vendor(device.idVendor)
            end
            
            if device.bDeviceClass then
                device.class_name = M.get_device_class(device.bDeviceClass)
            end
            
            -- определение типа устройства
            device.device_type = M.classify_device(device)
            
            table.insert(devices, device)
        end
    end
    
    handle:close()
    return devices
end

-- классификация устройства
function M.classify_device(dev)
    -- по классу
    local class_code = tonumber(dev.bDeviceClass, 16)
    
    if class_code == 0x08 then
        return "storage"
    elseif class_code == 0x03 then
        return "hid"
    elseif class_code == 0x01 then
        return "audio"
    elseif class_code == 0x07 then
        return "printer"
    elseif class_code == 0x09 then
        return "hub"
    elseif class_code == 0x0e then
        return "video"
    elseif class_code == 0xef then
        return "composite"
    end
    
    -- по производителю/названию
    local product = (dev.product or ""):lower()
    local vendor = (dev.vendor_name or ""):lower()
    
    if product:find("phone") or product:find("mobile") then
        return "phone"
    elseif product:find("camera") or product:find("webcam") then
        return "camera"
    elseif vendor:find("apple") then
        return "apple_device"
    elseif product:find("keyboard") then
        return "keyboard"
    elseif product:find("mouse") then
        return "mouse"
    end
    
    return "other"
end

-- анализ usb топологии
function M.analyze_topology()
    local topology = {
        root_hubs = {},
        devices_by_hub = {},
        tree = {}
    }
    
    local devices = M.parse_usb_devices()
    
    for _, dev in ipairs(devices) do
        -- определение root hub
        if dev.busnum and not dev.devnum:match(":") then
            table.insert(topology.root_hubs, dev)
        end
        
        -- группировка по шине
        if dev.busnum then
            if not topology.devices_by_hub[dev.busnum] then
                topology.devices_by_hub[dev.busnum] = {}
            end
            table.insert(topology.devices_by_hub[dev.busnum], dev)
        end
    end
    
    return topology
end

-- проверка на аномалии
function M.detect_anomalies(devices)
    local anomalies = {}
    
    for _, dev in ipairs(devices) do
        -- устройство без серийного номера
        if not dev.serial and dev.device_type ~= "hub" then
            -- это нормально для некоторых устройств, но отметим
            if dev.device_type == "storage" then
                table.insert(anomalies, {
                    type = "missing_serial",
                    severity = "medium",
                    device = dev,
                    description = "storage device without serial number"
                })
            end
        end
        
        -- подозрительный vendor id
        local vid = dev.idVendor or ""
        if vid:lower() == "0000" or vid:lower() == "ffff" then
            table.insert(anomalies, {
                type = "suspicious_vid",
                severity = "high",
                device = dev,
                description = "suspicious vendor id: " .. vid
            })
        end
        
        -- неизвестный производитель для известного класса
        if dev.vendor_name == "unknown" and dev.bDeviceClass then
            local class_code = tonumber(dev.bDeviceClass, 16)
            if class_code and class_code ~= 0x09 and class_code ~= 0xef then
                table.insert(anomalies, {
                    type = "unknown_vendor",
                    severity = "low",
                    device = dev,
                    description = "unknown vendor for class " .. dev.class_name
                })
            end
        end
    end
    
    return anomalies
end

-- статистика по usb
function M.get_statistics(devices)
    local stats = {
        total = #devices,
        by_class = {},
        by_vendor = {},
        by_type = {},
        high_speed = 0,
        super_speed = 0,
        hubs = 0,
        storage = 0,
        hid = 0
    }
    
    for _, dev in ipairs(devices) do
        -- по классу
        local class_name = dev.class_name or "unknown"
        stats.by_class[class_name] = (stats.by_class[class_name] or 0) + 1
        
        -- по производителю
        local vendor = dev.vendor_name or "unknown"
        stats.by_vendor[vendor] = (stats.by_vendor[vendor] or 0) + 1
        
        -- по типу
        local dtype = dev.device_type or "unknown"
        stats.by_type[dtype] = (stats.by_type[dtype] or 0) + 1
        
        -- скорость
        if dev.speed == "5000" then
            stats.super_speed = stats.super_speed + 1
        elseif dev.speed == "480" then
            stats.high_speed = stats.high_speed + 1
        end
        
        -- счетчики
        if dev.device_type == "hub" then
            stats.hubs = stats.hubs + 1
        elseif dev.device_type == "storage" then
            stats.storage = stats.storage + 1
        elseif dev.device_type == "hid" then
            stats.hid = stats.hid + 1
        end
    end
    
    return stats
end

-- вывод отчета
function M.print_report(devices)
    print("=" .. string.rep("-", 70))
    print("отчет анализа usb устройств")
    print("=" .. string.rep("-", 70))
    print("всего устройств: " .. #devices)
    print()
    
    local stats = M.get_statistics(devices)
    
    print("статистика:")
    print("  хабов: " .. stats.hubs)
    print("  накопителей: " .. stats.storage)
    print("  hid: " .. stats.hid)
    print("  usb 3.0+: " .. stats.super_speed)
    print("  usb 2.0: " .. stats.high_speed)
    print()
    
    print("по производителям:")
    for vendor, count in pairs(stats.by_vendor) do
        if count > 0 and vendor ~= "unknown" then
            print("  " .. vendor .. ": " .. count)
        end
    end
    print()
    
    print("список устройств:")
    for i, dev in ipairs(devices) do
        local desc = dev.product or dev.class_name or "unknown device"
        local vendor = dev.vendor_name or dev.idVendor or "unknown"
        local type_mark = ""
        
        if dev.device_type == "storage" then
            type_mark = " [storage]"
        elseif dev.device_type == "hub" then
            type_mark = " [hub]"
        elseif dev.device_type == "phone" then
            type_mark = " [phone]"
        end
        
        print(string.format("  %d. %s (%s)%s", i, desc, vendor, type_mark))
        print(string.format("     bus %s:%s | %s | %s",
            dev.busnum or "?",
            dev.devnum or "?",
            dev.class_name or "unknown",
            dev.speed and (dev.speed .. " Mbps") or "unknown speed"))
    end
    
    -- аномалии
    local anomalies = M.detect_anomalies(devices)
    if #anomalies > 0 then
        print()
        print("предупреждения:")
        for _, a in ipairs(anomalies) do
            local mark = "[*]"
            if a.severity == "high" then
                mark = "[!]"
            elseif a.severity == "medium" then
                mark = "[*]"
            end
            print(string.format("  %s %s: %s", mark, a.type, a.description))
        end
    end
    
    print("=" .. string.rep("-", 70))
end

return M
