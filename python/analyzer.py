#!/usr/bin/env python3
"""
Device Analyzer - Python Data Analysis Module
Advanced device discovery and analysis using Python
"""

import json
import subprocess
import re
import socket
import struct
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class USBDevice:
    """USB Device information"""
    vid: str
    pid: str
    vendor: str
    product: str
    serial: Optional[str] = None
    bus: Optional[str] = None
    device: Optional[str] = None
    speed: Optional[str] = None
    driver: Optional[str] = None


@dataclass
class NetworkDevice:
    """Network device information"""
    name: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    broadcast: Optional[str] = None
    netmask: Optional[str] = None
    status: str = "unknown"


@dataclass
class AnalysisReport:
    """Complete analysis report"""
    timestamp: str
    system_info: Dict[str, Any]
    usb_devices: List[USBDevice]
    network_devices: List[NetworkDevice]
    pci_devices: List[Dict[str, Any]]
    discoveries: Dict[str, Any]


class SystemAnalyzer:
    """Main system analysis class"""
    
    # USB Vendor ID database (common vendors)
    USB_VENDORS = {
        "046d": "Logitech",
        "0424": "Microchip/SMSC",
        "0781": "SanDisk",
        "0951": "Kingston",
        "0bda": "Realtek",
        "0c45": "Sonix Technology",
        "1058": "Western Digital",
        "1235": "Focusrite",
        "1a86": "QinHeng Electronics",
        "8086": "Intel Corporation",
        "8087": "Intel Corporation",
        "03eb": "Atmel Corporation",
        "2341": "Arduino SA",
        "2e8a": "Raspberry Pi",
        "0483": "STMicroelectronics",
        "090c": "Silicon Motion",
        "13fe": "Phison Electronics",
        "1b1c": "Corsair",
        "2516": "Cooler Master",
        "145f": "Trust International",
        "17ef": "Lenovo",
        "04e8": "Samsung Electronics",
        "1004": "LG Electronics",
        "12d1": "Huawei Technologies",
        "19d2": "ZTE Corporation",
        "0bb4": "HTC",
        "18d1": "Google Inc.",
        "05ac": "Apple Inc.",
        "04b3": "IBM",
        "045e": "Microsoft Corporation",
        "0451": "Texas Instruments",
        "0425": "Motorola",
        "0403": "Future Technology Devices (FTDI)",
        "067b": "Prolific Technology",
        "093a": "Pixart Imaging",
        "0ace": "ZyDAS Technology",
        "0b97": "O2 Micro",
        "0e8d": "MediaTek",
        "0fce": "Sony Ericsson",
        "1005": "I-O Data Device",
        "10c4": "Silicon Labs",
        "1410": "Novatel Wireless",
        "147e": "Upek (Biometric)",
        "1491": "Futaba",
        "04d9": "Holtek Semiconductor",
        "058f": "Alcor Micro",
        "1fc9": "NXP Semiconductors",
    }
    
    def __init__(self):
        self.data: Dict[str, Any] = {}
        self.report: Optional[AnalysisReport] = None
    
    def collect_all(self) -> AnalysisReport:
        """Collect all system information"""
        self.report = AnalysisReport(
            timestamp=datetime.now().isoformat(),
            system_info=self.get_system_info(),
            usb_devices=self.analyze_usb(),
            network_devices=self.analyze_network(),
            pci_devices=self.analyze_pci(),
            discoveries=self.run_discoveries()
        )
        return self.report
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get basic system information"""
        info = {
            "hostname": self._run_command("hostname"),
            "kernel": self._run_command("uname -r"),
            "arch": self._run_command("uname -m"),
            "os": self._get_os_info(),
            "uptime": self._run_command("uptime -p"),
            "load_avg": self._get_load_avg(),
        }
        
        # CPU information
        cpu_info = self._run_command("cat /proc/cpuinfo | grep 'model name' | head -1")
        if cpu_info:
            info["cpu_model"] = cpu_info.split(":", 1)[-1].strip() if ":" in cpu_info else cpu_info
        
        # Memory
        mem_info = self._run_command("free -h")
        if mem_info:
            info["memory"] = mem_info
        
        return info
    
    def analyze_usb(self) -> List[USBDevice]:
        """Analyze USB devices"""
        devices = []
        
        try:
            output = subprocess.check_output(["lsusb"], stderr=subprocess.DEVNULL, text=True)
            for line in output.strip().split("\n"):
                match = re.search(r"Bus (\d+) Device (\d+): ID ([0-9a-fA-F]{4}):([0-9a-fA-F]{4}) (.*)", line)
                if match:
                    bus, device, vid, pid, desc = match.groups()
                    vid = vid.lower()
                    pid = pid.lower()
                    
                    vendor = self.USB_VENDORS.get(vid, f"Unknown (0x{vid})")
                    
                    devices.append(USBDevice(
                        vid=vid,
                        pid=pid,
                        vendor=vendor,
                        product=desc.strip(),
                        bus=bus,
                        device=device
                    ))
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        # Try to get additional details from sysfs
        for dev in devices:
            self._enrich_usb_device(dev)
        
        return devices
    
    def _enrich_usb_device(self, device: USBDevice):
        """Add additional details from sysfs"""
        try:
            base_path = Path(f"/sys/bus/usb/devices/{device.bus}-{device.device}")
            if base_path.exists():
                # Get speed
                speed_file = base_path / "speed"
                if speed_file.exists():
                    device.speed = speed_file.read_text().strip()
                
                # Get serial
                serial_file = base_path / "serial"
                if serial_file.exists():
                    device.serial = serial_file.read_text().strip()
                
                # Find driver
                for driver_link in base_path.rglob("driver"):
                    if driver_link.is_symlink():
                        device.driver = driver_link.readlink().name
                        break
        except Exception:
            pass
    
    def analyze_network(self) -> List[NetworkDevice]:
        """Analyze network interfaces"""
        devices = []
        
        try:
            # Get interface list
            output = subprocess.check_output(
                ["ip", "addr", "show"], 
                stderr=subprocess.DEVNULL, 
                text=True
            )
            
            current_iface = None
            for line in output.split("\n"):
                # New interface
                match = re.match(r"(\d+): ([^:]+):", line)
                if match:
                    if current_iface:
                        devices.append(current_iface)
                    current_iface = NetworkDevice(name=match.group(2).strip())
                    if "UP" in line:
                        current_iface.status = "up"
                    if "DOWN" in line:
                        current_iface.status = "down"
                
                # MAC address
                elif current_iface and "link/ether" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        current_iface.mac = parts[1]
                
                # IP address
                elif current_iface and "inet " in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr_parts = parts[1].split("/")
                        current_iface.ip = addr_parts[0]
                        if len(addr_parts) > 1:
                            current_iface.netmask = addr_parts[1]
            
            if current_iface:
                devices.append(current_iface)
                
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return devices
    
    def analyze_pci(self) -> List[Dict[str, Any]]:
        """Analyze PCI devices"""
        devices = []
        
        try:
            output = subprocess.check_output(
                ["lspci", "-nn"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            for line in output.strip().split("\n"):
                match = re.match(r"(\S+) (.+?) \[(\w+)\]", line)
                if match:
                    slot, name, class_code = match.groups()
                    devices.append({
                        "slot": slot,
                        "name": name,
                        "class": class_code,
                        "raw": line
                    })
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return devices
    
    def run_discoveries(self) -> Dict[str, Any]:
        """Run various discovery protocols"""
        discoveries = {
            "arp_table": self._get_arp_table(),
            "neighbors": self._get_neighbors(),
            "routes": self._get_routes(),
            "listening_ports": self._get_listening_ports(),
        }
        
        # Try mDNS discovery
        discoveries["mdns"] = self._discover_mdns()
        
        return discoveries
    
    def _get_arp_table(self) -> List[Dict[str, str]]:
        """Get ARP table entries"""
        entries = []
        
        try:
            with open("/proc/net/arp", "r") as f:
                next(f)  # Skip header
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        entries.append({
                            "ip": parts[0],
                            "hw_type": parts[1],
                            "flags": parts[2],
                            "mac": parts[3],
                            "mask": parts[4],
                            "device": parts[5]
                        })
        except Exception:
            pass
        
        return entries
    
    def _get_neighbors(self) -> List[Dict[str, str]]:
        """Get IPv6 neighbors (NDP)"""
        neighbors = []
        
        try:
            output = subprocess.check_output(
                ["ip", "neigh", "show"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            for line in output.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 4:
                    neighbors.append({
                        "ip": parts[0],
                        "dev": parts[2],
                        "lladdr": parts[4] if len(parts) > 4 else None,
                        "state": parts[-1]
                    })
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return neighbors
    
    def _get_routes(self) -> List[Dict[str, str]]:
        """Get routing table"""
        routes = []
        
        try:
            output = subprocess.check_output(
                ["ip", "route", "show"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            for line in output.strip().split("\n"):
                routes.append({"route": line})
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return routes
    
    def _get_listening_ports(self) -> List[Dict[str, Any]]:
        """Get listening network ports"""
        ports = []
        
        try:
            # Read /proc/net/tcp for TCP listening ports
            with open("/proc/net/tcp", "r") as f:
                next(f)  # Skip header
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[1]
                        state = parts[3]
                        
                        # Listening state
                        if state == "0A":
                            ip_port = self._decode_proc_net_addr(local_addr)
                            if ip_port:
                                ports.append({
                                    "protocol": "tcp",
                                    "address": ip_port["ip"],
                                    "port": ip_port["port"],
                                    "raw": line.strip()
                                })
        except Exception:
            pass
        
        return ports
    
    def _decode_proc_net_addr(self, addr: str) -> Optional[Dict[str, Any]]:
        """Decode /proc/net format address"""
        try:
            ip_hex, port_hex = addr.split(":")
            ip_bytes = bytes.fromhex(ip_hex.zfill(8))
            ip = socket.inet_ntoa(struct.pack("<I", int(ip_hex, 16)))
            port = int(port_hex, 16)
            return {"ip": ip, "port": port}
        except Exception:
            return None
    
    def _discover_mdns(self) -> List[Dict[str, str]]:
        """Discover mDNS/Bonjour services"""
        services = []
        
        try:
            output = subprocess.check_output(
                ["avahi-browse", "-a", "-t", "-p"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5
            )
            
            for line in output.strip().split("\n"):
                if line.startswith("="):
                    parts = line.split(";")
                    if len(parts) >= 8:
                        services.append({
                            "interface": parts[1],
                            "protocol": parts[2],
                            "name": parts[3],
                            "type": parts[4],
                            "domain": parts[5],
                            "hostname": parts[6],
                            "address": parts[7]
                        })
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        return services
    
    def _get_os_info(self) -> Dict[str, str]:
        """Get OS distribution info"""
        os_info = {}
        
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("NAME="):
                        os_info["name"] = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("VERSION_ID="):
                        os_info["version"] = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("ID="):
                        os_info["id"] = line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
        
        return os_info
    
    def _get_load_avg(self) -> Dict[str, float]:
        """Get system load average"""
        try:
            with open("/proc/loadavg", "r") as f:
                parts = f.read().split()
                return {
                    "1min": float(parts[0]),
                    "5min": float(parts[1]),
                    "15min": float(parts[2])
                }
        except Exception:
            return {}
    
    def _run_command(self, cmd: str) -> str:
        """Run shell command and return output"""
        try:
            return subprocess.check_output(
                cmd,
                shell=True,
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return ""
    
    def export_json(self, filename: str = "device_report.json"):
        """Export report to JSON file"""
        if self.report is None:
            self.collect_all()
        
        # Convert dataclasses to dict
        data = {
            "timestamp": self.report.timestamp,
            "system_info": self.report.system_info,
            "usb_devices": [asdict(d) for d in self.report.usb_devices],
            "network_devices": [asdict(d) for d in self.report.network_devices],
            "pci_devices": self.report.pci_devices,
            "discoveries": self.report.discoveries
        }
        
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        
        return filename
    
    def generate_summary(self) -> str:
        """Generate human-readable summary"""
        if self.report is None:
            self.collect_all()
        
        lines = [
            "=" * 60,
            "DEVICE ANALYZER REPORT",
            "=" * 60,
            f"Generated: {self.report.timestamp}",
            "",
            "USB DEVICES:",
            "-" * 30,
        ]
        
        for dev in self.report.usb_devices[:10]:
            lines.append(f"  {dev.vendor} - {dev.product}")
            lines.append(f"    VID:PID: {dev.vid}:{dev.pid} | Bus: {dev.bus}")
        
        lines.extend([
            "",
            "NETWORK INTERFACES:",
            "-" * 30,
        ])
        
        for iface in self.report.network_devices:
            lines.append(f"  {iface.name}: {iface.status}")
            if iface.ip:
                lines.append(f"    IP: {iface.ip}")
            if iface.mac:
                lines.append(f"    MAC: {iface.mac}")
        
        lines.extend([
            "",
            "ACTIVE CONNECTIONS:",
            "-" * 30,
            f"  Listening ports: {len(self.report.discoveries.get('listening_ports', []))}",
            f"  ARP entries: {len(self.report.discoveries.get('arp_table', []))}",
            "",
            "=" * 60,
        ])
        
        return "\n".join(lines)
    
    # === расширенный функционал ===
    
    def analyze_usb_categories(self) -> Dict[str, List[USBDevice]]:
        """категоризация usb устройств по типам"""
        categories = {
            "storage": [],
            "input": [],
            "network": [],
            "audio": [],
            "video": [],
            "phones": [],
            "other": []
        }
        
        storage_vids = ["0781", "1058", "13fe", "090c", "058f"]  # sandisk, wd, phison, etc
        input_vids = ["046d", "145f", "093a"]  # logitech, trust, pixart
        audio_vids = ["1235", "0d8c"]  # focusrite, c-media
        phone_vids = ["04e8", "05ac", "18d1", "12d1", "0bb4"]  # samsung, apple, google, huawei, htc
        
        for dev in self.report.usb_devices if self.report else []:
            vid = dev.vid.lower()
            if vid in storage_vids:
                categories["storage"].append(dev)
            elif vid in input_vids:
                categories["input"].append(dev)
            elif vid in audio_vids:
                categories["audio"].append(dev)
            elif vid in phone_vids:
                categories["phones"].append(dev)
            elif "hub" in dev.product.lower():
                categories["network"].append(dev)
            else:
                categories["other"].append(dev)
        
        return categories
    
    def detect_usb_anomalies(self) -> List[Dict[str, Any]]:
        """обнаружение подозрительных usb устройств"""
        anomalies = []
        
        suspicious_vids = ["0000", "ffff", "1234", "dead", "beef"]
        
        for dev in self.report.usb_devices if self.report else []:
            vid = dev.vid.lower()
            
            # пустой серийный номер на устройстве, который должен его иметь
            if not dev.serial and dev.vendor not in ["Unknown", "Linux Foundation"]:
                if "storage" in dev.product.lower() or "disk" in dev.product.lower():
                    anomalies.append({
                        "device": dev,
                        "type": "missing_serial",
                        "severity": "medium",
                        "description": f"устройство {dev.vendor} без серийного номера"
                    })
            
            # подозрительный vendor id
            if vid in suspicious_vids:
                anomalies.append({
                    "device": dev,
                    "type": "suspicious_vid",
                    "severity": "high",
                    "description": f"подозрительный vendor id: {vid}"
                })
            
            # неизвестный производитель
            if "unknown" in dev.vendor.lower():
                anomalies.append({
                    "device": dev,
                    "type": "unknown_vendor",
                    "severity": "low",
                    "description": f"неизвестный производитель: {vid}:{dev.pid}"
                })
        
        return anomalies
    
    def analyze_network_security(self) -> Dict[str, Any]:
        """анализ сетевой безопасности"""
        security = {
            "open_ports": [],
            "risk_score": 0,
            "recommendations": []
        }
        
        dangerous_ports = {
            21: "ftp - нешифрованная передача",
            23: "telnet - нешифрованный доступ",
            25: "smtp - возможность спама",
            53: "dns - проверьте на открытый резолвер",
            80: "http - переключитесь на https",
            110: "pop3 - нешифрованная почта",
            143: "imap - нешифрованная почта",
            445: "smb - потенциально опасно извне",
            3306: "mysql - база данных открыта",
            3389: "rdp - удаленный доступ",
            5900: "vnc - удаленный доступ",
            8080: "http-proxy - проверьте конфигурацию"
        }
        
        for port_info in self.report.discoveries.get('listening_ports', []) if self.report else []:
            port = port_info.get('port', 0)
            if port in dangerous_ports:
                security["open_ports"].append({
                    "port": port,
                    "service": dangerous_ports[port],
                    "address": port_info.get('address', 'unknown')
                })
                security["risk_score"] += 10
        
        # рекомендации
        if security["risk_score"] > 50:
            security["recommendations"].append("критический: закройте ненужные порты с помощью фаервола")
        elif security["risk_score"] > 20:
            security["recommendations"].append("средний риск: проверьте открытые порты")
        
        # проверка на открытый ssh
        ssh_ports = [p for p in self.report.discoveries.get('listening_ports', []) if p.get('port') == 22] if self.report else []
        if ssh_ports:
            security["recommendations"].append("ssh открыт: убедитесь что используется key-based auth и fail2ban")
        
        return security
    
    def generate_html_report(self, filename: str = "device_report.html") -> str:
        """генерация html отчета"""
        if self.report is None:
            self.collect_all()
        
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>отчет анализатора устройств</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .section {{ background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4CAF50; color: white; }}
        tr:hover {{ background: #f9f9f9; }}
        .status-up {{ color: green; font-weight: bold; }}
        .status-down {{ color: red; }}
        .risk-high {{ color: #d32f2f; background: #ffebee; padding: 5px 10px; border-radius: 4px; }}
        .risk-medium {{ color: #f57c00; background: #fff3e0; padding: 5px 10px; border-radius: 4px; }}
        .risk-low {{ color: #388e3c; background: #e8f5e9; padding: 5px 10px; border-radius: 4px; }}
        .timestamp {{ color: #666; font-style: italic; }}
    </style>
</head>
<body>
    <h1>🔍 отчет анализатора устройств</h1>
    <p class="timestamp">сгенерировано: {self.report.timestamp}</p>
"""
        
        # системная информация
        html += f"""
    <div class="section">
        <h2>🖥️ системная информация</h2>
        <table>
            <tr><th>параметр</th><th>значение</th></tr>
            <tr><td>hostname</td><td>{self.report.system_info.get('hostname', 'N/A')}</td></tr>
            <tr><td>os</td><td>{self.report.system_info.get('os', {}).get('name', 'N/A')}</td></tr>
            <tr><td>kernel</td><td>{self.report.system_info.get('kernel', 'N/A')}</td></tr>
            <tr><td>uptime</td><td>{self.report.system_info.get('uptime', 'N/A')}</td></tr>
            <tr><td>cpu</td><td>{self.report.system_info.get('cpu_model', 'N/A')}</td></tr>
        </table>
    </div>
"""
        
        # usb устройства
        html += """
    <div class="section">
        <h2>🔌 usb устройства</h2>
        <table>
            <tr><th>производитель</th><th>продукт</th><th>vid:pid</th><th>серийный</th><th>скорость</th></tr>
"""
        for dev in self.report.usb_devices:
            serial = dev.serial or "N/A"
            speed = dev.speed or "unknown"
            html += f"            <tr><td>{dev.vendor}</td><td>{dev.product}</td><td>{dev.vid}:{dev.pid}</td><td>{serial}</td><td>{speed}</td></tr>\n"
        
        html += """        </table>
    </div>
"""
        
        # сетевые интерфейсы
        html += """
    <div class="section">
        <h2>🌐 сетевые интерфейсы</h2>
        <table>
            <tr><th>интерфейс</th><th>статус</th><th>ip</th><th>mac</th></tr>
"""
        for iface in self.report.network_devices:
            status_class = "status-up" if iface.status == "up" else "status-down"
            html += f'            <tr><td>{iface.name}</td><td class="{status_class}">{iface.status}</td><td>{iface.ip or "N/A"}</td><td>{iface.mac or "N/A"}</td></tr>\n'
        
        html += """        </table>
    </div>
"""
        
        # аномалии
        anomalies = self.detect_usb_anomalies()
        if anomalies:
            html += """
    <div class="section">
        <h2>⚠️ обнаруженные аномалии</h2>
        <table>
            <tr><th>устройство</th><th>тип</th><th>серьезность</th><th>описание</th></tr>
"""
            for anomaly in anomalies:
                severity_class = f"risk-{anomaly['severity']}"
                html += f'            <tr><td>{anomaly["device"].vendor}</td><td>{anomaly["type"]}</td><td class="{severity_class}">{anomaly["severity"]}</td><td>{anomaly["description"]}</td></tr>\n'
            html += """        </table>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        
        return filename
    
    def compare_with_previous(self, previous_report_path: str) -> Dict[str, Any]:
        """сравнение с предыдущим отчетом для выявления изменений"""
        try:
            with open(previous_report_path, "r") as f:
                previous = json.load(f)
        except Exception:
            return {"error": "не удалось загрузить предыдущий отчет"}
        
        changes = {
            "new_usb_devices": [],
            "removed_usb_devices": [],
            "new_network_interfaces": [],
            "status_changes": []
        }
        
        # сравнение usb
        prev_usb = {f"{d['vid']}:{d['pid']}:{d.get('serial', '')}": d for d in previous.get('usb_devices', [])}
        curr_usb = {f"{d.vid}:{d.pid}:{d.serial or ''}": d for d in self.report.usb_devices} if self.report else {}
        
        for key, dev in curr_usb.items():
            if key not in prev_usb:
                changes["new_usb_devices"].append(dev)
        
        for key, dev in prev_usb.items():
            if key not in curr_usb:
                changes["removed_usb_devices"].append(dev)
        
        return changes
    
    def predict_device_type(self, vid: str, pid: str, product_name: str) -> str:
        """простая эвристика для определения типа устройства"""
        product_lower = product_name.lower()
        
        keywords = {
            "storage": ["storage", "disk", "flash", "ssd", "hdd", "mass storage"],
            "keyboard": ["keyboard", "kbd"],
            "mouse": ["mouse", "optical", "wireless mouse"],
            "audio": ["audio", "sound", "headset", "microphone", "speaker"],
            "camera": ["camera", "webcam", "video"],
            "phone": ["phone", "android", "iphone", "mobile", "mtp", "adb"],
            "printer": ["printer", "print"],
            "network": ["ethernet", "network", "wifi", "wireless", "bluetooth"]
        }
        
        for device_type, words in keywords.items():
            if any(word in product_lower for word in words):
                return device_type
        
        # проверка по базе вендоров
        phone_vendors = ["05ac", "04e8", "18d1", "12d1", "0bb4", "19d2", "0fce"]
        if vid.lower() in phone_vendors:
            return "phone"
        
        return "unknown"
    
    def export_csv(self, filename: str = "devices.csv") -> str:
        """экспорт usb устройств в csv"""
        import csv
        
        if self.report is None:
            self.collect_all()
        
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["vendor", "product", "vid", "pid", "serial", "bus", "device", "speed", "predicted_type"])
            
            for dev in self.report.usb_devices:
                predicted = self.predict_device_type(dev.vid, dev.pid, dev.product)
                writer.writerow([dev.vendor, dev.product, dev.vid, dev.pid, 
                               dev.serial or "", dev.bus or "", dev.device or "",
                               dev.speed or "", predicted])
        
        return filename
    
    def get_statistics(self) -> Dict[str, Any]:
        """статистика по всем устройствам"""
        if self.report is None:
            self.collect_all()
        
        categories = self.analyze_usb_categories()
        
        return {
            "total_usb": len(self.report.usb_devices),
            "total_network": len(self.report.network_devices),
            "total_pci": len(self.report.pci_devices),
            "usb_by_category": {k: len(v) for k, v in categories.items()},
            "network_up": sum(1 for n in self.report.network_devices if n.status == "up"),
            "unknown_devices": sum(1 for d in self.report.usb_devices if "unknown" in d.vendor.lower()),
            "vendor_distribution": self._get_vendor_distribution()
        }
    
    def _get_vendor_distribution(self) -> Dict[str, int]:
        """распределение по производителям"""
        dist = {}
        for dev in self.report.usb_devices if self.report else []:
            vendor = dev.vendor.split()[0] if dev.vendor else "Unknown"
            dist[vendor] = dist.get(vendor, 0) + 1
        return dict(sorted(dist.items(), key=lambda x: x[1], reverse=True)[:10])


def main():
    """Main entry point"""
    analyzer = SystemAnalyzer()
    
    print("Device Analyzer - Python Analysis Module")
    print("=" * 60)
    
    # Collect and display
    analyzer.collect_all()
    print(analyzer.generate_summary())
    
    # Export to JSON
    filename = analyzer.export_json()
    print(f"\nFull report exported to: {filename}")


if __name__ == "__main__":
    main()
