#!/usr/bin/env python3
"""
модуль мониторинга железа
сбор метрик процессора, памяти, температур и дисков
"""

import os
import re
import time
import json
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path


@dataclass
class CPUMetrics:
    """метрики процессора"""
    usage_percent: float
    frequency_mhz: Optional[int]
    temperature_c: Optional[float]
    core_count: int
    thread_count: int
    load_average: Tuple[float, float, float]


@dataclass
class MemoryMetrics:
    """метрики памяти"""
    total_mb: int
    used_mb: int
    free_mb: int
    available_mb: int
    buffers_mb: int
    cached_mb: int
    swap_total_mb: int
    swap_used_mb: int
    percent_used: float


@dataclass
class DiskMetrics:
    """метрики диска"""
    device: str
    mount_point: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent_used: float
    filesystem: str
    io_read_mb: Optional[float]
    io_write_mb: Optional[float]


@dataclass
class NetworkMetrics:
    """метрики сети"""
    interface: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int
    tx_errors: int
    rx_speed_mbps: Optional[float]
    tx_speed_mbps: Optional[float]


@dataclass
class ThermalMetrics:
    """термические метрики"""
    zone_name: str
    temperature_c: float
    type: str  # cpu, gpu, battery, etc


@dataclass
class SystemSnapshot:
    """полный снимок системы"""
    timestamp: str
    cpu: CPUMetrics
    memory: MemoryMetrics
    disks: List[DiskMetrics]
    network: List[NetworkMetrics]
    thermal: List[ThermalMetrics]
    uptime_seconds: int
    processes_count: int


class HardwareMonitor:
    """основной класс мониторинга железа"""
    
    def __init__(self):
        self.history: List[SystemSnapshot] = []
        self.max_history = 1000
    
    def get_cpu_metrics(self) -> CPUMetrics:
        """сбор метрик процессора"""
        # загрузка cpu из /proc/stat
        with open('/proc/stat', 'r') as f:
            line = f.readline()
            fields = line.split()[1:]
            user, nice, system, idle = map(int, fields[:4])
            total = user + nice + system + idle
            usage = (user + nice + system) / total * 100 if total > 0 else 0
        
        # количество ядер
        core_count = os.cpu_count() or 1
        
        # частота cpu
        freq = None
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'cpu MHz' in line:
                        freq = int(float(line.split(':')[1].strip()))
                        break
        except:
            pass
        
        # температура
        temp = self._get_cpu_temperature()
        
        # load average
        load_avg = os.getloadavg()
        
        return CPUMetrics(
            usage_percent=round(usage, 2),
            frequency_mhz=freq,
            temperature_c=temp,
            core_count=core_count,
            thread_count=core_count,
            load_average=load_avg
        )
    
    def _get_cpu_temperature(self) -> Optional[float]:
        """получение температуры процессора"""
        thermal_paths = [
            '/sys/class/thermal/thermal_zone0/temp',
            '/sys/class/thermal/thermal_zone1/temp',
            '/sys/class/hwmon/hwmon0/temp1_input',
            '/sys/class/hwmon/hwmon1/temp1_input',
        ]
        
        for path in thermal_paths:
            try:
                with open(path, 'r') as f:
                    temp_milli = int(f.read().strip())
                    return temp_milli / 1000.0
            except:
                continue
        return None
    
    def get_memory_metrics(self) -> MemoryMetrics:
        """сбор метрик памяти"""
        mem_info = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if ':' in line:
                    key, value = line.split(':')
                    mem_info[key.strip()] = int(value.split()[0]) // 1024  # convert to MB
        
        total = mem_info.get('MemTotal', 0)
        free = mem_info.get('MemFree', 0)
        available = mem_info.get('MemAvailable', free)
        buffers = mem_info.get('Buffers', 0)
        cached = mem_info.get('Cached', 0)
        
        used = total - available
        
        swap_total = mem_info.get('SwapTotal', 0)
        swap_free = mem_info.get('SwapFree', 0)
        swap_used = swap_total - swap_free
        
        percent = (used / total * 100) if total > 0 else 0
        
        return MemoryMetrics(
            total_mb=total,
            used_mb=used,
            free_mb=free,
            available_mb=available,
            buffers_mb=buffers,
            cached_mb=cached,
            swap_total_mb=swap_total,
            swap_used_mb=swap_used,
            percent_used=round(percent, 2)
        )
    
    def get_disk_metrics(self) -> List[DiskMetrics]:
        """сбор метрик дисков"""
        disks = []
        
        # чтение mount points
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    device, mount_point, fs_type = parts[0], parts[1], parts[2]
                    
                    # skip virtual filesystems
                    if fs_type in ('proc', 'sysfs', 'devpts', 'tmpfs', 'devtmpfs', 'cgroup'):
                        continue
                    if device.startswith('/dev/loop'):
                        continue
                    
                    try:
                        stat = os.statvfs(mount_point)
                        total = stat.f_blocks * stat.f_frsize
                        free = stat.f_bavail * stat.f_frsize
                        used = total - free
                        
                        total_gb = total / (1024**3)
                        used_gb = used / (1024**3)
                        free_gb = free / (1024**3)
                        percent = (used / total * 100) if total > 0 else 0
                        
                        disks.append(DiskMetrics(
                            device=device,
                            mount_point=mount_point,
                            total_gb=round(total_gb, 2),
                            used_gb=round(used_gb, 2),
                            free_gb=round(free_gb, 2),
                            percent_used=round(percent, 2),
                            filesystem=fs_type,
                            io_read_mb=None,
                            io_write_mb=None
                        ))
                    except:
                        continue
        
        return disks
    
    def get_network_metrics(self) -> List[NetworkMetrics]:
        """сбор сетевых метрик"""
        interfaces = []
        
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()[2:]  # skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 9:
                    iface = parts[0].rstrip(':')
                    
                    # skip loopback
                    if iface == 'lo':
                        continue
                    
                    rx_bytes = int(parts[1])
                    rx_packets = int(parts[2])
                    rx_errors = int(parts[3])
                    tx_bytes = int(parts[9])
                    tx_packets = int(parts[10])
                    tx_errors = int(parts[11])
                    
                    interfaces.append(NetworkMetrics(
                        interface=iface,
                        rx_bytes=rx_bytes,
                        tx_bytes=tx_bytes,
                        rx_packets=rx_packets,
                        tx_packets=tx_packets,
                        rx_errors=rx_errors,
                        tx_errors=tx_errors,
                        rx_speed_mbps=None,
                        tx_speed_mbps=None
                    ))
        
        return interfaces
    
    def get_thermal_metrics(self) -> List[ThermalMetrics]:
        """сбор термических метрик"""
        thermal_zones = []
        
        thermal_path = Path('/sys/class/thermal')
        if thermal_path.exists():
            for zone_dir in thermal_path.glob('thermal_zone*'):
                try:
                    with open(zone_dir / 'temp', 'r') as f:
                        temp = int(f.read().strip()) / 1000.0
                    
                    zone_type = 'unknown'
                    try:
                        with open(zone_dir / 'type', 'r') as f:
                            zone_type = f.read().strip()
                    except:
                        pass
                    
                    thermal_zones.append(ThermalMetrics(
                        zone_name=zone_dir.name,
                        temperature_c=temp,
                        type=zone_type
                    ))
                except:
                    continue
        
        return thermal_zones
    
    def get_uptime(self) -> int:
        """получение uptime в секундах"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = int(float(f.read().split()[0]))
                return uptime_seconds
        except:
            return 0
    
    def get_process_count(self) -> int:
        """подсчет процессов"""
        try:
            return len([p for p in os.listdir('/proc') if p.isdigit()])
        except:
            return 0
    
    def capture_snapshot(self) -> SystemSnapshot:
        """создание снимка системы"""
        snapshot = SystemSnapshot(
            timestamp=datetime.now().isoformat(),
            cpu=self.get_cpu_metrics(),
            memory=self.get_memory_metrics(),
            disks=self.get_disk_metrics(),
            network=self.get_network_metrics(),
            thermal=self.get_thermal_metrics(),
            uptime_seconds=self.get_uptime(),
            processes_count=self.get_process_count()
        )
        
        # сохранение в историю
        self.history.append(snapshot)
        if len(self.history) > self.max_history:
            self.history.pop(0)
        
        return snapshot
    
    def export_json(self, filename: str = "hardware_metrics.json") -> str:
        """экспорт в json"""
        if not self.history:
            self.capture_snapshot()
        
        data = {
            "snapshots": [asdict(s) for s in self.history[-100:]],  # last 100
            "summary": self._generate_summary()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def _generate_summary(self) -> Dict:
        """генерация сводки по истории"""
        if not self.history:
            return {}
        
        cpu_temps = [s.cpu.temperature_c for s in self.history if s.cpu.temperature_c]
        mem_usage = [s.memory.percent_used for s in self.history]
        
        return {
            "snapshots_count": len(self.history),
            "time_span_minutes": len(self.history) * 5,  # assuming 5min intervals
            "avg_cpu_temp": round(sum(cpu_temps) / len(cpu_temps), 2) if cpu_temps else None,
            "max_cpu_temp": max(cpu_temps) if cpu_temps else None,
            "avg_memory_usage": round(sum(mem_usage) / len(mem_usage), 2) if mem_usage else 0,
            "current_uptime_hours": self.history[-1].uptime_seconds / 3600 if self.history else 0
        }
    
    def check_alerts(self) -> List[Dict]:
        """проверка критических значений"""
        alerts = []
        
        if not self.history:
            return alerts
        
        latest = self.history[-1]
        
        # проверка температуры
        if latest.cpu.temperature_c and latest.cpu.temperature_c > 80:
            alerts.append({
                "level": "warning",
                "component": "cpu",
                "message": f"высокая температура CPU: {latest.cpu.temperature_c}C",
                "threshold": 80
            })
        
        # проверка памяти
        if latest.memory.percent_used > 90:
            alerts.append({
                "level": "critical",
                "component": "memory",
                "message": f"критическое использование памяти: {latest.memory.percent_used}%",
                "threshold": 90
            })
        elif latest.memory.percent_used > 80:
            alerts.append({
                "level": "warning",
                "component": "memory",
                "message": f"высокое использование памяти: {latest.memory.percent_used}%",
                "threshold": 80
            })
        
        # проверка дисков
        for disk in latest.disks:
            if disk.percent_used > 90:
                alerts.append({
                    "level": "warning",
                    "component": f"disk_{disk.device}",
                    "message": f"диск {disk.mount_point} заполнен на {disk.percent_used}%",
                    "threshold": 90
                })
        
        # проверка swap
        if latest.memory.swap_total_mb > 0:
            swap_usage = latest.memory.swap_used_mb / latest.memory.swap_total_mb * 100
            if swap_usage > 50:
                alerts.append({
                    "level": "warning",
                    "component": "swap",
                    "message": f"активное использование swap: {swap_usage:.1f}%",
                    "threshold": 50
                })
        
        return alerts
    
    def print_report(self):
        """вывод текстового отчета"""
        if not self.history:
            self.capture_snapshot()
        
        latest = self.history[-1]
        
        print("=" * 60)
        print("отчет мониторинга железа")
        print("=" * 60)
        print(f"время: {latest.timestamp}")
        print(f"uptime: {latest.uptime_seconds // 3600}ч { (latest.uptime_seconds % 3600) // 60}м")
        print(f"процессов: {latest.processes_count}")
        print()
        
        print("[cpu]")
        print(f"  загрузка: {latest.cpu.usage_percent}%")
        print(f"  частота: {latest.cpu.frequency_mhz} MHz" if latest.cpu.frequency_mhz else "  частота: N/A")
        print(f"  температура: {latest.cpu.temperature_c}C" if latest.cpu.temperature_c else "  температура: N/A")
        print(f"  ядер: {latest.cpu.core_count}")
        print(f"  load avg: {latest.cpu.load_average[0]:.2f}, {latest.cpu.load_average[1]:.2f}, {latest.cpu.load_average[2]:.2f}")
        print()
        
        print("[память]")
        print(f"  всего: {latest.memory.total_mb} MB")
        print(f"  использовано: {latest.memory.used_mb} MB ({latest.memory.percent_used}%)")
        print(f"  доступно: {latest.memory.available_mb} MB")
        print(f"  swap: {latest.memory.swap_used_mb}/{latest.memory.swap_total_mb} MB")
        print()
        
        print("[диски]")
        for disk in latest.disks:
            print(f"  {disk.device} ({disk.mount_point}): {disk.used_gb}/{disk.total_gb} GB ({disk.percent_used}%)")
        print()
        
        print("[сеть]")
        for net in latest.network:
            rx_mb = net.rx_bytes / (1024**2)
            tx_mb = net.tx_bytes / (1024**2)
            print(f"  {net.interface}: RX {rx_mb:.2f} MB, TX {tx_mb:.2f} MB")
        print()
        
        alerts = self.check_alerts()
        if alerts:
            print("[предупреждения]")
            for alert in alerts:
                level_mark = "[!]" if alert["level"] == "critical" else "[*]"
                print(f"  {level_mark} {alert['message']}")
        else:
            print("[предупреждения] нет")
        
        print("=" * 60)


def main():
    """тестовый запуск"""
    monitor = HardwareMonitor()
    monitor.capture_snapshot()
    monitor.print_report()
    
    # сохранение
    filename = monitor.export_json()
    print(f"\nметрики сохранены в: {filename}")


if __name__ == "__main__":
    main()
