#!/usr/bin/env python3
"""
расширенный модуль анализа устройств
обнаружение, классификация и анализ usb и сетевых устройств
"""

import json
import re
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
from datetime import datetime


@dataclass
class USBDevice:
    """структура usb устройства"""
    vid: str
    pid: str
    vendor: str
    product: str
    serial: Optional[str] = None
    bus: Optional[str] = None
    device: Optional[str] = None
    speed: Optional[str] = None
    manufacturer: Optional[str] = None
    driver: Optional[str] = None


@dataclass
class NetworkDevice:
    """структура сетевого устройства"""
    name: str
    mac: Optional[str] = None
    ip: Optional[str] = None
    status: str = "unknown"
    type: str = "unknown"
    is_wireless: bool = False
    is_virtual: bool = False


@dataclass
class PCIDevice:
    """структура pci устройства"""
    vendor_id: str
    device_id: str
    vendor_name: str
    device_name: str
    class_code: str
    subclass: str
    revision: str


class USBVendorDB:
    """база данных вендоров usb"""
    
    VENDORS = {
        "046d": "Logitech",
        "04e8": "Samsung",
        "05ac": "Apple",
        "0781": "SanDisk",
        "0951": "Kingston",
        "0bda": "Realtek",
        "0c45": "Microdia",
        "13fe": "Kingston",
        "18d1": "Google",
        "1a2c": "China",
        "1b1c": "Corsair",
        "1c6b": "Phison",
        "2516": "Cooler Master",
        "29ea": "KWorld",
        "413c": "Dell",
        "8086": "Intel",
        "8087": "Intel",
        "090c": "Feiya",
        "1058": "Western Digital",
        "058f": "Alcor Micro",
        "0480": "Toshiba",
        "040b": "Weltrend",
        "045e": "Microsoft",
        "0461": "Primax",
        "0463": "MGE UPS Systems",
        "046a": "Cherry",
        "046b": "American Power Conversion",
        "046c": "Saitek",
        "046d": "Logitech",
        "0471": "Philips",
        "047b": "Silitek",
        "047d": "Kensington",
        "047e": "Wiebetech",
        "047f": "Nortel",
        "0480": "Sun",
        "0481": "Reserved",
        "0482": "Kyocera",
        "0483": "STMicroelectronics",
        "0484": "Foxconn",
        "0485": "Lenovo",
        "0486": "Acer",
        "0487": "ST-Ericsson",
        "0488": "Cypress",
        "0489": "Foxconn",
        "048a": "Sagem",
        "048b": "MosArt",
        "048c": "Vishub",
        "048d": "ITE Tech",
        "048e": "EDIMAX",
        "048f": "Reserved",
        "0490": "Uni-Trend",
        "0491": "Obihai",
        "0492": "ECS",
        "0493": "Hewlett Packard",
        "0494": "Hewlett Packard",
        "0495": "Hewlett Packard",
        "0496": "Hewlett Packard",
        "0497": "Hewlett Packard",
        "0498": "Hewlett Packard",
        "0499": "Hewlett Packard",
        "049a": "Hewlett Packard",
        "049b": "Hewlett Packard",
        "049c": "Hewlett Packard",
        "049d": "Hewlett Packard",
        "049e": "Hewlett Packard",
        "049f": "Hewlett Packard",
        "04a0": "Hewlett Packard",
        "04a1": "Hewlett Packard",
        "04a2": "Hewlett Packard",
        "04a3": "Hewlett Packard",
        "04a4": "Hewlett Packard",
        "04a5": "Hewlett Packard",
        "04a6": "Hewlett Packard",
        "04a7": "Hewlett Packard",
        "04a8": "Hewlett Packard",
        "04a9": "Canon",
        "04aa": "Dicom",
        "04ab": "Chrontel",
        "04ac": "MicroScan",
        "04ad": "Novatel",
        "04ae": "Nikon",
        "04af": "Panasonic",
        "04b0": "Nikon",
        "04b1": "Panasonic",
        "04b3": "IBM",
        "04b4": "Cypress",
        "04b5": "ROHM",
        "04b6": "Winbond",
        "04b7": "Hewlett Packard",
        "04b8": "Seiko Epson",
        "04b9": "Samsung",
        "04ba": "Touhid",
        "04bb": "I-O Data",
        "04bd": "Toshiba",
        "04be": "Toshiba",
        "04bf": "Toshiba",
        "04c1": "Fujitsu",
        "04c2": "Methode",
        "04c3": "Maxell",
        "04c4": "Lockheed Martin",
        "04c5": "Fujitsu",
        "04c6": "Toshiba",
        "04c7": "Philips",
        "04c8": "Konica",
        "04c9": "Compaq",
        "04ca": "Lite-On",
        "04cb": "Fujitsu",
        "04cc": "Alps",
        "04cd": "Texas Instruments Japan",
        "04ce": "ScanLogic",
        "04cf": "Mitsumi",
        "04d0": "D-Link",
        "04d1": "Mazda",
        "04d2": "Apta",
        "04d3": "JVC",
        "04d4": "Hagiwara",
        "04d5": "Fuji Xerox",
        "04d6": "Fujitsu",
        "04d7": "Fujitsu",
        "04d8": "Future Technology",
        "04d9": "Good Way",
        "04da": "Panasonic",
        "04db": "Infineon",
        "04dc": "Hagiwara",
        "04dd": "Sharp",
        "04de": "STMicroelectronics",
        "04df": "iBluetooth",
        "04e0": "NEC",
        "04e1": "IOI",
        "04e2": "Semtech",
        "04e3": "Mitsumi",
        "04e4": "Mitsubishi",
        "04e5": "Texas Instruments",
        "04e6": "SCM Microsystems",
        "04e7": "Elo TouchSystems",
        "04e8": "Samsung Electronics",
        "04e9": "PC-Tel",
        "04ea": "Brother",
        "04eb": "Fujitsu",
        "04ec": "Aoke",
        "04ed": "Sharp",
        "04ef": "Wave Systems",
        "04f0": "NEC",
        "04f1": "Melco",
        "04f2": "Chicony Electronics",
        "04f3": "Elan Microelectronics",
        "04f4": "CSR",
        "04f5": "NZXT",
        "04f6": "TDK",
        "04f7": "Smklink",
        "04f8": "Chunghwa",
        "04f9": "Sunplus",
        "04fa": "Dallas Semiconductor",
        "04fb": "Biostar Microtech",
        "04fc": "Sunplus",
        "04fd": "Sunplus",
        "04fe": "Pacific Digital",
        "04ff": "Willtek",
        "0500": "Delta Electronics",
        "0501": "System Talks",
        "0502": "Mobility",
        "0503": "Siemens",
        "0504": "Digitus",
        "0506": "Toshiba",
        "0507": "NEC",
        "0508": "Hewlett Packard",
        "0509": "Maudio",
        "050a": "Cytiva",
        "050b": "Network Alchemy",
        "050c": "Lucent",
        "050d": "Belkin",
        "050e": "Clevo",
        "050f": "Digital Persona",
        "0510": "Sejin",
        "0511": "Nuscan",
        "0512": "Agilent",
        "0513": "NEC",
        "0514": "Shin-Etsukaken",
        "0515": "Workbit",
        "0516": "Tripath",
        "0517": "Chaintek",
        "0518": "C-Media",
        "0519": "Star Micronics",
        "051a": "Wipro",
        "051b": "Technol Seven",
        "051c": "Ids Icon",
        "051d": "National Semiconductor",
        "051e": "Signtech",
        "051f": "Oak",
        "0520": "ATI",
        "0521": "Microtek",
        "0522": "Aten",
        "0523": "Keycon",
        "0524": "Genoa",
        "0525": "Netchip",
        "0526": "Temic Mhs",
        "0527": "Funai",
        "0528": "Fujitsu",
        "0529": "Aladdin",
        "052a": "Cypress",
        "052b": "Moschip Semiconductor",
        "052c": "Mobility Electronics",
        "052d": "Toshiba",
        "052e": "Phillips",
        "052f": "Toshiba",
        "0530": "Toshiba",
        "0531": "Toshiba",
        "0532": "Toshiba",
        "0533": "Toshiba",
        "0534": "Toshiba",
        "0535": "Toshiba",
        "0536": "Toshiba",
        "0537": "Toshiba",
        "0538": "Toshiba",
        "0539": "Toshiba",
        "053a": "Toshiba",
        "053b": "Toshiba",
        "053c": "Toshiba",
        "053d": "Toshiba",
        "053e": "Toshiba",
        "053f": "Toshiba",
        "0540": "Nippon Dics",
        "0541": "Sharp",
        "0542": "Nvidia",
        "0543": "Silver I",
        "0544": "Gyration",
        "0545": "Viewsonic",
        "0546": "Celestix",
        "0547": "Chaintek",
        "0548": "Lite-On",
        "0549": "Canon",
        "054a": "Panasonic",
        "054b": "Philips",
        "054c": "Sony",
        "054d": "Aishi",
        "054e": "Toshiba",
        "054f": "Toshiba",
        "0550": "Toshiba",
        "0551": "Qualcomm",
        "0552": "Musical"
    }
    
    @classmethod
    def get_vendor(cls, vid: str) -> str:
        """получение названия вендора по vid"""
        return cls.VENDORS.get(vid.lower(), f"Unknown ({vid})")


class DeviceClassifier:
    """классификатор типов устройств"""
    
    # ключевые слова для определения типа
    KEYWORDS = {
        "storage": ["storage", "disk", "flash", "ssd", "hdd", "mass", "usb flash", "pendrive"],
        "keyboard": ["keyboard", "kbd", "keypad"],
        "mouse": ["mouse", "optical mouse", "wireless mouse", "trackball"],
        "audio": ["audio", "sound", "headset", "microphone", "speaker", "headphone", "mic"],
        "video": ["camera", "webcam", "video", "cam"],
        "phone": ["phone", "android", "iphone", "mobile", "mtp", "adb", "samsung", "xiaomi"],
        "printer": ["printer", "print", "scanner"],
        "network": ["ethernet", "network", "wifi", "wireless", "bluetooth", "lan"],
        "input": ["gamepad", "joystick", "controller", "tablet"],
        "hub": ["hub", "dock"]
    }
    
    # vid известных производителей телефонов
    PHONE_VIDS = ["05ac", "04e8", "18d1", "12d1", "0bb4", "19d2", "0fce", "2717", "2987"]
    
    @classmethod
    def classify(cls, vid: str, pid: str, product: str) -> str:
        """определение типа устройства"""
        product_lower = product.lower()
        vid_lower = vid.lower()
        
        # проверка по ключевым словам
        for device_type, keywords in cls.KEYWORDS.items():
            if any(keyword in product_lower for keyword in keywords):
                return device_type
        
        # проверка по вендору телефона
        if vid_lower in cls.PHONE_VIDS:
            return "phone"
        
        return "unknown"
    
    @classmethod
    def get_icon(cls, device_type: str) -> str:
        """получение иконки для типа устройства"""
        icons = {
            "storage": "💾",
            "keyboard": "⌨️",
            "mouse": "🖱️",
            "audio": "🎧",
            "video": "📷",
            "phone": "📱",
            "printer": "🖨️",
            "network": "🌐",
            "input": "🎮",
            "hub": "🔌",
            "unknown": "❓"
        }
        return icons.get(device_type, "❓")


class NetworkAnalyzer:
    """анализатор сетевых устройств и конфигурации"""
    
    # опасные порты для открытого доступа
    DANGEROUS_PORTS = {
        21: ("ftp", "нешифрованная передача файлов"),
        23: ("telnet", "нешифрованный удаленный доступ"),
        25: ("smtp", "открытая отправка почты"),
        53: ("dns", "возможен dns amplification"),
        80: ("http", "переключитесь на https"),
        110: ("pop3", "нешифрованная почта"),
        143: ("imap", "нешифрованная почта"),
        445: ("smb", "высокий риск извне"),
        3306: ("mysql", "база данных открыта"),
        3389: ("rdp", "удаленный рабочий стол"),
        5900: ("vnc", "удаленный доступ"),
        6379: ("redis", "база данных открыта"),
        8080: ("http-proxy", "проверьте конфигурацию"),
        9200: ("elasticsearch", "поисковый движок открыт")
    }
    
    @classmethod
    def analyze_security(cls, open_ports: List[int]) -> Dict:
        """анализ безопасности открытых портов"""
        risks = []
        score = 0
        
        for port in open_ports:
            if port in cls.DANGEROUS_PORTS:
                service, risk = cls.DANGEROUS_PORTS[port]
                risks.append({
                    "port": port,
                    "service": service,
                    "risk": risk,
                    "severity": "high" if port in [23, 445, 3389, 5900] else "medium"
                })
                score += 20 if port in [23, 445, 3389, 5900] else 10
        
        # определение уровня риска
        if score >= 50:
            level = "critical"
            recommendation = "немедленно закройте ненужные порты с помощью фаервола"
        elif score >= 30:
            level = "high"
            recommendation = "проверьте необходимость открытых портов"
        elif score >= 10:
            level = "medium"
            recommendation = "рекомендуется ограничить доступ к некритичным сервисам"
        else:
            level = "low"
            recommendation = "конфигурация в порядке"
        
        return {
            "risk_level": level,
            "risk_score": score,
            "open_risks": risks,
            "recommendation": recommendation
        }
    
    @staticmethod
    def detect_virtual_iface(name: str) -> bool:
        """определение виртуального интерфейса"""
        virtual_prefixes = ["docker", "br-", "veth", "virbr", "vmnet", "tun", "tap", "lo"]
        return any(name.startswith(prefix) for prefix in virtual_prefixes)
    
    @staticmethod
    def detect_wireless_iface(name: str) -> bool:
        """определение беспроводного интерфейса"""
        wireless_indicators = ["wlan", "wlp", "ath", "wl", "wifi", "ra", "eth"]
        # проверка через iw
        try:
            result = subprocess.run(
                ["iw", name, "info"],
                capture_output=True,
                text=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return any(ind in name.lower() for ind in wireless_indicators)


class DeviceReport:
    """генератор отчетов об устройствах"""
    
    def __init__(self, usb_devices: List[USBDevice], 
                 network_devices: List[NetworkDevice],
                 pci_devices: List[PCIDevice] = None):
        self.usb = usb_devices
        self.network = network_devices
        self.pci = pci_devices or []
        self.timestamp = datetime.now().isoformat()
    
    def generate_summary(self) -> str:
        """текстовая сводка"""
        lines = [
            "=" * 60,
            "📊 ОТЧЕТ АНАЛИЗАТОРА УСТРОЙСТВ",
            "=" * 60,
            f"время: {self.timestamp}",
            "",
            f"🔌 USB устройств: {len(self.usb)}",
            f"🌐 Сетевых интерфейсов: {len(self.network)}",
            f"🖥️ PCI устройств: {len(self.pci)}",
            ""
        ]
        
        # классификация usb
        by_type = {}
        for dev in self.usb:
            dev_type = DeviceClassifier.classify(dev.vid, dev.pid, dev.product)
            by_type[dev_type] = by_type.get(dev_type, 0) + 1
        
        if by_type:
            lines.append("📂 USB по категориям:")
            for dtype, count in sorted(by_type.items(), key=lambda x: -x[1]):
                icon = DeviceClassifier.get_icon(dtype)
                lines.append(f"  {icon} {dtype}: {count}")
            lines.append("")
        
        # сетевая статистика
        up_count = sum(1 for n in self.network if n.status == "up")
        lines.append(f"📡 Активных интерфейсов: {up_count}/{len(self.network)}")
        
        # беспроводные сети
        wifi_count = sum(1 for n in self.network if n.is_wireless)
        if wifi_count > 0:
            lines.append(f"📶 WiFi интерфейсов: {wifi_count}")
        
        lines.append("=" * 60)
        return "\n".join(lines)
    
    def to_json(self) -> str:
        """экспорт в json"""
        data = {
            "timestamp": self.timestamp,
            "usb_devices": [asdict(d) for d in self.usb],
            "network_devices": [asdict(d) for d in self.network],
            "pci_devices": [asdict(d) for d in self.pci],
            "statistics": {
                "total_usb": len(self.usb),
                "total_network": len(self.network),
                "total_pci": len(self.pci),
                "active_network": sum(1 for n in self.network if n.status == "up")
            }
        }
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    def generate_html(self) -> str:
        """генерация html отчета"""
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>отчет анализатора устройств</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }}
        h1 {{ color: #667eea; text-align: center; margin-bottom: 10px; }}
        .timestamp {{ text-align: center; color: #666; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 36px; font-weight: bold; }}
        .stat-label {{ font-size: 14px; opacity: 0.9; }}
        h2 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .device-type {{ display: inline-block; padding: 5px 10px; border-radius: 15px; font-size: 12px; font-weight: bold; }}
        .type-storage {{ background: #4CAF50; color: white; }}
        .type-phone {{ background: #2196F3; color: white; }}
        .type-audio {{ background: #FF9800; color: white; }}
        .type-network {{ background: #9C27B0; color: white; }}
        .status-up {{ color: #4CAF50; font-weight: bold; }}
        .status-down {{ color: #F44336; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 отчет анализатора устройств</h1>
        <p class="timestamp">{self.timestamp}</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{len(self.usb)}</div>
                <div class="stat-label">USB устройств</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(self.network)}</div>
                <div class="stat-label">сетевых интерфейсов</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(self.pci)}</div>
                <div class="stat-label">PCI устройств</div>
            </div>
        </div>
"""
        
        # USB устройства
        if self.usb:
            html += """
        <h2>🔌 USB устройства</h2>
        <table>
            <tr><th>тип</th><th>вендор</th><th>продукт</th><th>vid:pid</th><th>серийный</th></tr>
"""
            for dev in self.usb:
                dev_type = DeviceClassifier.classify(dev.vid, dev.pid, dev.product)
                icon = DeviceClassifier.get_icon(dev_type)
                html += f"""            <tr>
                <td><span class="device-type type-{dev_type}">{icon} {dev_type}</span></td>
                <td>{dev.vendor}</td>
                <td>{dev.product}</td>
                <td>{dev.vid}:{dev.pid}</td>
                <td>{dev.serial or "N/A"}</td>
            </tr>
"""
            html += "        </table>"
        
        # сетевые интерфейсы
        if self.network:
            html += """
        <h2>🌐 сетевые интерфейсы</h2>
        <table>
            <tr><th>имя</th><th>MAC</th><th>IP</th><th>статус</th><th>тип</th></tr>
"""
            for iface in self.network:
                status_class = "status-up" if iface.status == "up" else "status-down"
                wifi_icon = "📶 " if iface.is_wireless else ""
                html += f"""            <tr>
                <td>{wifi_icon}{iface.name}</td>
                <td>{iface.mac or "N/A"}</td>
                <td>{iface.ip or "N/A"}</td>
                <td class="{status_class}">{iface.status}</td>
                <td>{iface.type}</td>
            </tr>
"""
            html += "        </table>"
        
        html += """
    </div>
</body>
</html>
"""
        return html


def main():
    """демонстрационный запуск"""
    print("запуск расширенного анализатора устройств...")
    print("\nдоступные классы:")
    print(f"  - USBVendorDB: база из {len(USBVendorDB.VENDORS)} вендоров")
    print(f"  - DeviceClassifier: {len(DeviceClassifier.KEYWORDS)} категорий")
    print(f"  - NetworkAnalyzer: {len(NetworkAnalyzer.DANGEROUS_PORTS)} опасных портов")
    print(f"  - DeviceReport: генератор отчетов")


if __name__ == "__main__":
    main()
