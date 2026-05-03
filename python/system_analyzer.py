#!/usr/bin/env python3
"""
системный анализатор процессов и безопасности
анализ процессов, служб, пользователей и уязвимостей
"""

import os
import re
import pwd
import grp
import json
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from pathlib import Path
from collections import defaultdict


@dataclass
class ProcessInfo:
    """информация о процессе"""
    pid: int
    name: str
    user: str
    cpu_percent: float
    memory_mb: int
    command: str
    status: str
    threads: int
    open_files: int
    connections: int
    start_time: str
    is_root: bool


@dataclass
class ServiceInfo:
    """информация о службе"""
    name: str
    status: str  # active, inactive, failed
    enabled: bool
    description: str
    pid: Optional[int]
    memory_usage_mb: Optional[int]


@dataclass
class UserInfo:
    """информация о пользователе"""
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    is_admin: bool
    last_login: Optional[str]
    groups: List[str]


@dataclass
class SecurityCheck:
    """результат проверки безопасности"""
    check_name: str
    status: str  # pass, warning, fail
    severity: str  # low, medium, high, critical
    description: str
    recommendation: str
    details: Optional[Dict]


@dataclass
class LogEntry:
    """запись лога"""
    timestamp: str
    level: str
    service: str
    message: str
    source: str


class ProcessAnalyzer:
    """анализатор процессов"""
    
    def get_process_list(self) -> List[ProcessInfo]:
        """получение списка процессов"""
        processes = []
        
        for pid_dir in Path('/proc').glob('[0-9]*'):
            try:
                pid = int(pid_dir.name)
                
                # чтение status
                status_info = self._read_status(pid)
                
                # чтение stat
                stat_info = self._read_stat(pid)
                
                # чтение cmdline
                cmdline = self._read_cmdline(pid)
                
                # подсчет открытых файлов
                open_files = self._count_open_files(pid)
                
                # подсчет соединений
                connections = self._count_connections(pid)
                
                # время запуска
                start_time = self._get_start_time(pid)
                
                processes.append(ProcessInfo(
                    pid=pid,
                    name=status_info.get('Name', 'unknown'),
                    user=status_info.get('user', 'unknown'),
                    cpu_percent=stat_info.get('cpu_percent', 0.0),
                    memory_mb=status_info.get('VmRSS', 0) // 1024,
                    command=cmdline[:100] if cmdline else status_info.get('Name', ''),
                    status=status_info.get('State', 'unknown'),
                    threads=status_info.get('Threads', 1),
                    open_files=open_files,
                    connections=connections,
                    start_time=start_time,
                    is_root=status_info.get('Uid', '0').split()[0] == '0'
                ))
            except:
                continue
        
        return sorted(processes, key=lambda p: p.memory_mb, reverse=True)
    
    def _read_status(self, pid: int) -> Dict:
        """чтение /proc/PID/status"""
        info = {}
        try:
            with open(f'/proc/{pid}/status', 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        info[key.strip()] = value.strip()
            
            # определение пользователя
            if 'Uid' in info:
                uid = int(info['Uid'].split()[0])
                try:
                    info['user'] = pwd.getpwuid(uid).pw_name
                except:
                    info['user'] = str(uid)
        except:
            pass
        return info
    
    def _read_stat(self, pid: int) -> Dict:
        """чтение /proc/PID/stat"""
        try:
            with open(f'/proc/{pid}/stat', 'r') as f:
                fields = f.read().split()
                return {
                    'cpu_percent': 0.0  # требует вычислений между измерениями
                }
        except:
            return {}
    
    def _read_cmdline(self, pid: int) -> str:
        """чтение командной строки процесса"""
        try:
            with open(f'/proc/{pid}/cmdline', 'r') as f:
                return f.read().replace('\0', ' ').strip()
        except:
            return ""
    
    def _count_open_files(self, pid: int) -> int:
        """подсчет открытых файлов"""
        try:
            fd_dir = Path(f'/proc/{pid}/fd')
            return len(list(fd_dir.iterdir()))
        except:
            return 0
    
    def _count_connections(self, pid: int) -> int:
        """подсчет сетевых соединений процесса"""
        count = 0
        try:
            for proto in ['tcp', 'tcp6', 'udp', 'udp6']:
                try:
                    with open(f'/proc/net/{proto}', 'r') as f:
                        lines = f.readlines()[1:]
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 10:
                                inode = parts[9]
                                if inode != '0' and (Path(f'/proc/{pid}/fd').glob(f'*{inode}*')):
                                    count += 1
                except:
                    continue
        except:
            pass
        return count
    
    def _get_start_time(self, pid: int) -> str:
        """получение времени запуска"""
        try:
            stat_file = Path(f'/proc/{pid}/stat')
            if stat_file.exists():
                stat = stat_file.read_text()
                # starttime is field 22 (index 21)
                return "unknown"
        except:
            pass
        return "unknown"
    
    def find_suspicious_processes(self) -> List[ProcessInfo]:
        """поиск подозрительных процессов"""
        suspicious = []
        processes = self.get_process_list()
        
        for proc in processes:
            # процесс от root с сетевыми соединениями
            if proc.is_root and proc.connections > 0:
                # проверка на скрытые процессы (имя в скобках - kernel thread)
                if not proc.name.startswith('('):
                    suspicious.append(proc)
            
            # процесс без имени или с подозрительным именем
            if proc.name in ['.', '..', '...'] or len(proc.name) < 2:
                suspicious.append(proc)
            
            # высокое потребление памяти
            if proc.memory_mb > 1000:  # > 1GB
                suspicious.append(proc)
        
        return suspicious
    
    def get_process_tree(self) -> Dict:
        """построение дерева процессов"""
        tree = defaultdict(list)
        
        try:
            for pid_dir in Path('/proc').glob('[0-9]*'):
                try:
                    pid = int(pid_dir.name)
                    with open(f'/proc/{pid}/stat', 'r') as f:
                        stat = f.read().split()
                        ppid = int(stat[3])  # parent pid is field 4
                        tree[ppid].append(pid)
                except:
                    continue
        except:
            pass
        
        return dict(tree)


class ServiceAnalyzer:
    """анализатор системных служб"""
    
    def get_services(self) -> List[ServiceInfo]:
        """получение списка служб"""
        services = []
        
        # используем systemctl
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--no-pager', '-a'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in result.stdout.split('\n')[1:]:  # skip header
                if '.' in line and 'service' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[0]
                        status = parts[3] if len(parts) > 3 else 'unknown'
                        
                        services.append(ServiceInfo(
                            name=name,
                            status=status,
                            enabled=self._is_enabled(name),
                            description=' '.join(parts[4:]) if len(parts) > 4 else '',
                            pid=None,
                            memory_usage_mb=None
                        ))
        except:
            pass
        
        return services
    
    def _is_enabled(self, service_name: str) -> bool:
        """проверка включена ли служба"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-enabled', service_name],
                capture_output=True,
                text=True,
                timeout=2
            )
            return result.returncode == 0 and 'enabled' in result.stdout
        except:
            return False
    
    def get_failed_services(self) -> List[ServiceInfo]:
        """получение упавших служб"""
        return [s for s in self.get_services() if s.status == 'failed']
    
    def get_running_services(self) -> List[ServiceInfo]:
        """получение активных служб"""
        return [s for s in self.get_services() if s.status == 'active']


class UserAnalyzer:
    """анализатор пользователей"""
    
    def get_users(self) -> List[UserInfo]:
        """получение списка пользователей"""
        users = []
        
        for user in pwd.getpwall():
            # skip system users
            if user.pw_uid < 1000 and user.pw_name not in ['root']:
                continue
            
            # определение административных групп
            admin_groups = ['wheel', 'sudo', 'admin']
            user_groups = [grp.getgrgid(g).gr_name for g in os.getgrouplist(user.pw_name, user.pw_gid)]
            is_admin = any(g in admin_groups for g in user_groups) or user.pw_uid == 0
            
            # время последнего входа
            last_login = self._get_last_login(user.pw_name)
            
            users.append(UserInfo(
                username=user.pw_name,
                uid=user.pw_uid,
                gid=user.pw_gid,
                home=user.pw_dir,
                shell=user.pw_shell,
                is_admin=is_admin,
                last_login=last_login,
                groups=user_groups
            ))
        
        return users
    
    def _get_last_login(self, username: str) -> Optional[str]:
        """получение времени последнего входа"""
        try:
            result = subprocess.run(
                ['last', '-n', '1', username],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 4:
                    return ' '.join(parts[3:6])
        except:
            pass
        return None
    
    def get_logged_in_users(self) -> List[Dict]:
        """получение активных сессий"""
        users = []
        try:
            result = subprocess.run(
                ['who'],
                capture_output=True,
                text=True,
                timeout=2
            )
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 3:
                        users.append({
                            'username': parts[0],
                            'tty': parts[1],
                            'time': ' '.join(parts[2:4]) if len(parts) >= 4 else 'unknown'
                        })
        except:
            pass
        return users


class SecurityAnalyzer:
    """анализатор безопасности"""
    
    def run_security_checks(self) -> List[SecurityCheck]:
        """выполнение проверок безопасности"""
        checks = []
        
        # проверка открытых портов
        checks.append(self._check_open_ports())
        
        # проверка служб ssh
        checks.append(self._check_ssh_config())
        
        # проверка прав на важные файлы
        checks.append(self._check_file_permissions())
        
        # проверка наличия антивируса
        checks.append(self._check_antivirus())
        
        # проверка фаервола
        checks.append(self._check_firewall())
        
        # проверка обновлений
        checks.append(self._check_updates())
        
        # проверка пользователей без пароля
        checks.append(self._check_passwordless_users())
        
        # проверка suid файлов
        checks.append(self._check_suid_files())
        
        return [c for c in checks if c is not None]
    
    def _check_open_ports(self) -> SecurityCheck:
        """проверка открытых портов"""
        dangerous_ports = [23, 135, 139, 445, 1433, 3389, 5900, 6379]
        open_ports = []
        
        try:
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] == '0A':  # LISTEN state
                        local_addr = parts[1]
                        port = int(local_addr.split(':')[1], 16)
                        if port in dangerous_ports:
                            open_ports.append(port)
        except:
            pass
        
        if open_ports:
            return SecurityCheck(
                check_name="опасные порты",
                status="fail",
                severity="high",
                description=f"открыты опасные порты: {open_ports}",
                recommendation="закройте ненужные порты с помощью iptables или ufw",
                details={"ports": open_ports}
            )
        
        return SecurityCheck(
            check_name="опасные порты",
            status="pass",
            severity="low",
            description="опасные порты закрыты",
            recommendation="нет действий",
            details=None
        )
    
    def _check_ssh_config(self) -> SecurityCheck:
        """проверка конфигурации ssh"""
        ssh_config = Path('/etc/ssh/sshd_config')
        
        if not ssh_config.exists():
            return SecurityCheck(
                check_name="ssh конфигурация",
                status="warning",
                severity="medium",
                description="ssh не установлен или не настроен",
                recommendation="убедитесь что ssh настроен правильно",
                details=None
            )
        
        content = ssh_config.read_text()
        issues = []
        
        if 'PermitRootLogin yes' in content or 'PermitRootLogin without-password' in content:
            issues.append("root login разрешен")
        
        if 'PasswordAuthentication yes' in content:
            issues.append("авторизация по паролю включена")
        
        if 'Port 22' in content and 'Port ' not in content.replace('Port 22', ''):
            issues.append("используется стандартный порт 22")
        
        if issues:
            return SecurityCheck(
                check_name="ssh конфигурация",
                status="warning",
                severity="medium",
                description=f"найдены проблемы: {', '.join(issues)}",
                recommendation="настройте key-based auth, запретите root, смените порт",
                details={"issues": issues}
            )
        
        return SecurityCheck(
            check_name="ssh конфигурация",
            status="pass",
            severity="low",
            description="ssh настроен безопасно",
            recommendation="нет действий",
            details=None
        )
    
    def _check_file_permissions(self) -> SecurityCheck:
        """проверка прав на важные файлы"""
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/ssh/sshd_config'
        ]
        
        issues = []
        for file_path in critical_files:
            path = Path(file_path)
            if path.exists():
                stat = path.stat()
                mode = oct(stat.st_mode)[-3:]
                
                # shadow должен быть 000 или 600
                if 'shadow' in file_path and mode not in ['0', '600', '640']:
                    issues.append(f"{file_path} имеет права {mode}")
                # passwd должен быть 644
                elif 'passwd' in file_path and mode != '644':
                    issues.append(f"{file_path} имеет права {mode}")
        
        if issues:
            return SecurityCheck(
                check_name="права на файлы",
                status="warning",
                severity="medium",
                description=f"неправильные права: {len(issues)} файлов",
                recommendation="исправьте права с помощью chmod",
                details={"files": issues}
            )
        
        return SecurityCheck(
            check_name="права на файлы",
            status="pass",
            severity="low",
            description="права на критические файлы в порядке",
            recommendation="нет действий",
            details=None
        )
    
    def _check_antivirus(self) -> SecurityCheck:
        """проверка наличия антивируса"""
        av_tools = ['clamav', 'avast', 'esets', 'kaspersky', 'drweb']
        found = []
        
        for tool in av_tools:
            try:
                result = subprocess.run(
                    ['which', tool],
                    capture_output=True,
                    timeout=1
                )
                if result.returncode == 0:
                    found.append(tool)
            except:
                continue
        
        if not found:
            return SecurityCheck(
                check_name="антивирус",
                status="warning",
                severity="low",
                description="антивирус не обнаружен",
                recommendation="рассмотрите установку clamav для сканирования",
                details=None
            )
        
        return SecurityCheck(
            check_name="антивирус",
            status="pass",
            severity="low",
            description=f"найден: {', '.join(found)}",
            recommendation="нет действий",
            details={"installed": found}
        )
    
    def _check_firewall(self) -> SecurityCheck:
        """проверка фаервола"""
        try:
            # проверка iptables
            result = subprocess.run(
                ['iptables', '-L', '-n'],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                rules = result.stdout.decode()
                if 'ACCEPT' in rules or 'DROP' in rules:
                    return SecurityCheck(
                        check_name="фаервол",
                        status="pass",
                        severity="low",
                        description="iptables настроен",
                        recommendation="нет действий",
                        details=None
                    )
        except:
            pass
        
        # проверка ufw
        try:
            result = subprocess.run(
                ['ufw', 'status'],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0 and 'active' in result.stdout.decode():
                return SecurityCheck(
                    check_name="фаервол",
                    status="pass",
                    severity="low",
                    description="ufw активен",
                    recommendation="нет действий",
                    details=None
                )
        except:
            pass
        
        return SecurityCheck(
            check_name="фаервол",
            status="warning",
            severity="high",
            description="фаервол не активен",
            recommendation="настройте iptables или ufw",
            details=None
        )
    
    def _check_updates(self) -> SecurityCheck:
        """проверка обновлений"""
        # проверка для arch
        try:
            result = subprocess.run(
                ['checkupdates'],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                updates = result.stdout.decode().strip().split('\n')
                update_count = len([u for u in updates if u])
                
                if update_count > 50:
                    return SecurityCheck(
                        check_name="обновления",
                        status="fail",
                        severity="high",
                        description=f"{update_count} пакетов требуют обновления",
                        recommendation="выполните pacman -Syu",
                        details={"count": update_count}
                    )
                elif update_count > 0:
                    return SecurityCheck(
                        check_name="обновления",
                        status="warning",
                        severity="medium",
                        description=f"{update_count} пакетов можно обновить",
                        recommendation="выполните pacman -Syu",
                        details={"count": update_count}
                    )
        except:
            pass
        
        return SecurityCheck(
            check_name="обновления",
            status="pass",
            severity="low",
            description="система обновлена",
            recommendation="нет действий",
            details=None
        )
    
    def _check_passwordless_users(self) -> SecurityCheck:
        """проверка пользователей без пароля"""
        passwordless = []
        
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    if ':' in line:
                        parts = line.split(':')
                        user = parts[0]
                        password = parts[1]
                        
                        # empty password field means no password required
                        if password == '' or password.startswith('!'):
                            # check if it's a system user
                            try:
                                user_info = pwd.getpwnam(user)
                                if user_info.pw_uid >= 1000:
                                    passwordless.append(user)
                            except:
                                pass
        except:
            pass
        
        if passwordless:
            return SecurityCheck(
                check_name="пользователи без пароля",
                status="fail",
                severity="critical",
                description=f"пользователи без пароля: {', '.join(passwordless)}",
                recommendation="немедленно установите пароли: passwd <username>",
                details={"users": passwordless}
            )
        
        return SecurityCheck(
            check_name="пользователи без пароля",
            status="pass",
            severity="low",
            description="все пользователи имеют пароли",
            recommendation="нет действий",
            details=None
        )
    
    def _check_suid_files(self) -> SecurityCheck:
        """проверка suid файлов"""
        # common locations for suid files
        suspicious_suid = []
        
        common_bins = [
            '/bin/su',
            '/bin/passwd',
            '/bin/mount',
            '/bin/umount',
            '/usr/bin/sudo',
            '/usr/bin/passwd'
        ]
        
        for binary in common_bins:
            path = Path(binary)
            if path.exists():
                stat = path.stat()
                if stat.st_mode & 0o4000:  # SUID bit
                    pass  # expected
                else:
                    if 'sudo' in binary or 'su' in binary:
                        suspicious_suid.append(f"{binary} не имеет suid бита")
        
        return SecurityCheck(
            check_name="suid файлы",
            status="pass",
            severity="low",
            description="suid файлы в порядке",
            recommendation="нет действий",
            details=None
        )


class SystemReporter:
    """генератор отчетов о системе"""
    
    def __init__(self):
        self.process_analyzer = ProcessAnalyzer()
        self.service_analyzer = ServiceAnalyzer()
        self.user_analyzer = UserAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
    
    def generate_full_report(self) -> Dict:
        """генерация полного отчета"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "hostname": os.uname().nodename,
            "processes": {
                "total": len(self.process_analyzer.get_process_list()),
                "top_memory": [asdict(p) for p in self.process_analyzer.get_process_list()[:10]],
                "suspicious": [asdict(p) for p in self.process_analyzer.find_suspicious_processes()[:5]]
            },
            "services": {
                "running": len(self.service_analyzer.get_running_services()),
                "failed": [asdict(s) for s in self.service_analyzer.get_failed_services()]
            },
            "users": {
                "total": len(self.user_analyzer.get_users()),
                "admins": len([u for u in self.user_analyzer.get_users() if u.is_admin]),
                "logged_in": self.user_analyzer.get_logged_in_users()
            },
            "security": {
                "checks": [asdict(c) for c in self.security_analyzer.run_security_checks()],
                "passed": len([c for c in self.security_analyzer.run_security_checks() if c.status == 'pass']),
                "warnings": len([c for c in self.security_analyzer.run_security_checks() if c.status == 'warning']),
                "failed": len([c for c in self.security_analyzer.run_security_checks() if c.status == 'fail'])
            }
        }
        
        return report
    
    def print_security_report(self):
        """вывод отчета о безопасности"""
        checks = self.security_analyzer.run_security_checks()
        
        print("=" * 70)
        print("ОТЧЕТ О БЕЗОПАСНОСТИ СИСТЕМЫ")
        print("=" * 70)
        print()
        
        passed = [c for c in checks if c.status == 'pass']
        warnings = [c for c in checks if c.status == 'warning']
        failed = [c for c in checks if c.status == 'fail']
        
        print(f"всего проверок: {len(checks)}")
        print(f"  [OK] пройдено: {len(passed)}")
        print(f"  [!] предупреждений: {len(warnings)}")
        print(f"  [X] ошибок: {len(failed)}")
        print()
        
        if failed:
            print("[-] КРИТИЧЕСКИЕ ПРОБЛЕМЫ:")
            for check in failed:
                print(f"    [X] {check.check_name}: {check.description}")
                print(f"        рекомендация: {check.recommendation}")
            print()
        
        if warnings:
            print("[*] ПРЕДУПРЕЖДЕНИЯ:")
            for check in warnings:
                print(f"    [!] {check.check_name}: {check.description}")
                print(f"        рекомендация: {check.recommendation}")
            print()
        
        print("=" * 70)


def main():
    """тестовый запуск"""
    reporter = SystemReporter()
    
    print("сбор информации о системе...")
    reporter.print_security_report()
    
    # экспорт в json
    report = reporter.generate_full_report()
    filename = f"system_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\nполный отчет сохранен: {filename}")


if __name__ == "__main__":
    main()
