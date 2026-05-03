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
