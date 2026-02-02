#!/usr/bin/env python3
"""
Network Configuration Backup Tool
Automated backup with Git versioning, compliance checking, and change detection

Author: Tamer Khalifa (CCIE #68867)
GitHub: https://github.com/tamersaid2022
"""

import os
import sys
import re
import json
import logging
import argparse
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import difflib

import yaml
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Netmiko for device connections
try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    print("⚠️ Netmiko not installed. Install with: pip install netmiko")

# GitPython for version control
try:
    from git import Repo, InvalidGitRepositoryError
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False
    print("⚠️ GitPython not installed. Install with: pip install gitpython")

# Rich for beautiful output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_backup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Device:
    """Network device configuration"""
    name: str
    host: str
    device_type: str
    username: str = ""
    password: str = ""
    port: int = 22
    timeout: int = 30
    groups: List[str] = field(default_factory=list)
    backup_commands: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class BackupResult:
    """Result of a backup operation"""
    device_name: str
    success: bool
    config: str = ""
    error: str = ""
    changed: bool = False
    size_bytes: int = 0
    duration_seconds: float = 0
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ComplianceResult:
    """Result of compliance check"""
    device_name: str
    rule_name: str
    passed: bool
    severity: str = "MEDIUM"
    message: str = ""
    remediation: str = ""


@dataclass
class DiffResult:
    """Configuration diff result"""
    device_name: str
    old_config: str
    new_config: str
    changes: List[str] = field(default_factory=list)
    added_lines: int = 0
    removed_lines: int = 0


# =============================================================================
# DEFAULT BACKUP COMMANDS
# =============================================================================

DEFAULT_COMMANDS = {
    "cisco_ios": ["show running-config"],
    "cisco_xe": ["show running-config"],
    "cisco_xr": ["show running-config"],
    "cisco_nxos": ["show running-config"],
    "cisco_asa": ["show running-config"],
    "juniper_junos": ["show configuration | display set"],
    "arista_eos": ["show running-config"],
    "paloalto_panos": ["show config running"],
    "fortinet": ["show full-configuration"],
    "hp_procurve": ["show running-config"],
    "linux": ["cat /etc/network/interfaces"],
}


# =============================================================================
# INVENTORY MANAGER
# =============================================================================

class InventoryManager:
    """Manages device inventory"""
    
    def __init__(self, inventory_file: str):
        self.inventory_file = Path(inventory_file)
        self.devices: Dict[str, Device] = {}
        self.groups: Dict[str, List[str]] = {}
        self.defaults: Dict = {}
        self._load_inventory()
    
    def _load_inventory(self):
        """Load inventory from YAML file"""
        if not self.inventory_file.exists():
            logger.warning(f"Inventory file not found: {self.inventory_file}")
            return
        
        with open(self.inventory_file) as f:
            data = yaml.safe_load(f)
        
        self.defaults = data.get("defaults", {})
        
        # Load devices
        for name, config in data.get("devices", {}).items():
            device = Device(
                name=name,
                host=config.get("host", name),
                device_type=config.get("device_type", "cisco_ios"),
                username=config.get("username", self.defaults.get("username", os.getenv("NETWORK_USER", "admin"))),
                password=config.get("password", self.defaults.get("password", os.getenv("NETWORK_PASSWORD", ""))),
                port=config.get("port", self.defaults.get("port", 22)),
                timeout=config.get("timeout", self.defaults.get("timeout", 30)),
                groups=config.get("groups", []),
                backup_commands=config.get("backup_commands", []),
                enabled=config.get("enabled", True)
            )
            self.devices[name] = device
            
            # Build group index
            for group in device.groups:
                if group not in self.groups:
                    self.groups[group] = []
                self.groups[group].append(name)
        
        # Load group-specific commands
        for group_name, group_config in data.get("groups", {}).items():
            if "backup_commands" in group_config:
                for device_name in self.groups.get(group_name, []):
                    if device_name in self.devices and not self.devices[device_name].backup_commands:
                        self.devices[device_name].backup_commands = group_config["backup_commands"]
        
        logger.info(f"📋 Loaded {len(self.devices)} devices from inventory")
    
    def get_device(self, name: str) -> Optional[Device]:
        """Get device by name"""
        return self.devices.get(name)
    
    def get_devices_by_group(self, group: str) -> List[Device]:
        """Get all devices in a group"""
        device_names = self.groups.get(group, [])
        return [self.devices[name] for name in device_names if name in self.devices]
    
    def get_all_devices(self) -> List[Device]:
        """Get all enabled devices"""
        return [d for d in self.devices.values() if d.enabled]


# =============================================================================
# DEVICE CONNECTOR
# =============================================================================

class DeviceConnector:
    """Handles device connections and command execution"""
    
    def __init__(self, device: Device):
        self.device = device
        self.connection = None
    
    def connect(self) -> bool:
        """Establish SSH connection"""
        if not NETMIKO_AVAILABLE:
            logger.error("Netmiko not available")
            return False
        
        try:
            self.connection = ConnectHandler(
                device_type=self.device.device_type,
                host=self.device.host,
                username=self.device.username,
                password=self.device.password,
                port=self.device.port,
                timeout=self.device.timeout
            )
            logger.debug(f"✅ Connected to {self.device.name}")
            return True
            
        except NetmikoAuthenticationException as e:
            logger.error(f"❌ Authentication failed for {self.device.name}: {e}")
            return False
            
        except NetmikoTimeoutException as e:
            logger.error(f"❌ Connection timeout for {self.device.name}: {e}")
            return False
            
        except Exception as e:
            logger.error(f"❌ Connection error for {self.device.name}: {e}")
            return False
    
    def disconnect(self):
        """Close connection"""
        if self.connection:
            self.connection.disconnect()
            self.connection = None
    
    def execute_command(self, command: str) -> str:
        """Execute command and return output"""
        if not self.connection:
            return ""
        
        try:
            output = self.connection.send_command(command, read_timeout=60)
            return output
        except Exception as e:
            logger.error(f"Command execution error on {self.device.name}: {e}")
            return ""
    
    def get_config(self) -> str:
        """Get device configuration"""
        if not self.connection:
            return ""
        
        # Use custom commands if defined, otherwise use defaults
        commands = self.device.backup_commands or DEFAULT_COMMANDS.get(self.device.device_type, ["show running-config"])
        
        config_parts = []
        for cmd in commands:
            output = self.execute_command(cmd)
            if output:
                config_parts.append(f"! Command: {cmd}\n{output}")
        
        return "\n\n".join(config_parts)


# =============================================================================
# GIT MANAGER
# =============================================================================

class GitManager:
    """Manages Git versioning of backups"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.repo = None
        self._init_repo()
    
    def _init_repo(self):
        """Initialize or open Git repository"""
        if not GIT_AVAILABLE:
            logger.warning("GitPython not available - version control disabled")
            return
        
        try:
            self.repo = Repo(self.repo_path)
            logger.debug(f"📂 Opened Git repository: {self.repo_path}")
        except InvalidGitRepositoryError:
            # Initialize new repository
            self.repo_path.mkdir(parents=True, exist_ok=True)
            self.repo = Repo.init(self.repo_path)
            logger.info(f"📂 Initialized new Git repository: {self.repo_path}")
    
    def commit_changes(self, message: str) -> Optional[str]:
        """Commit all changes"""
        if not self.repo:
            return None
        
        try:
            # Stage all changes
            self.repo.git.add(A=True)
            
            # Check if there are changes to commit
            if not self.repo.is_dirty() and not self.repo.untracked_files:
                logger.debug("No changes to commit")
                return None
            
            # Commit
            commit = self.repo.index.commit(message)
            logger.info(f"📝 Git commit: {commit.hexsha[:8]} - {message}")
            return commit.hexsha
            
        except Exception as e:
            logger.error(f"Git commit error: {e}")
            return None
    
    def get_file_history(self, filepath: str, limit: int = 10) -> List[Dict]:
        """Get commit history for a file"""
        if not self.repo:
            return []
        
        history = []
        try:
            commits = list(self.repo.iter_commits(paths=filepath, max_count=limit))
            for commit in commits:
                history.append({
                    "hash": commit.hexsha[:8],
                    "message": commit.message.strip(),
                    "author": str(commit.author),
                    "date": commit.committed_datetime.isoformat()
                })
        except Exception as e:
            logger.error(f"Error getting file history: {e}")
        
        return history
    
    def get_file_at_commit(self, filepath: str, commit_hash: str) -> str:
        """Get file content at specific commit"""
        if not self.repo:
            return ""
        
        try:
            commit = self.repo.commit(commit_hash)
            blob = commit.tree / filepath
            return blob.data_stream.read().decode('utf-8')
        except Exception as e:
            logger.error(f"Error getting file at commit: {e}")
            return ""


# =============================================================================
# COMPLIANCE CHECKER
# =============================================================================

class ComplianceChecker:
    """Checks configurations against compliance rules"""
    
    def __init__(self, rules_file: str = None):
        self.rules = []
        if rules_file:
            self._load_rules(rules_file)
    
    def _load_rules(self, rules_file: str):
        """Load compliance rules from YAML"""
        rules_path = Path(rules_file)
        if not rules_path.exists():
            logger.warning(f"Rules file not found: {rules_file}")
            return
        
        with open(rules_path) as f:
            data = yaml.safe_load(f)
        
        self.rules = data.get("rules", [])
        logger.info(f"📋 Loaded {len(self.rules)} compliance rules")
    
    def check_config(self, device_name: str, config: str) -> List[ComplianceResult]:
        """Check configuration against all rules"""
        results = []
        
        for rule in self.rules:
            result = self._check_rule(device_name, config, rule)
            results.append(result)
        
        return results
    
    def _check_rule(self, device_name: str, config: str, rule: Dict) -> ComplianceResult:
        """Check a single rule against configuration"""
        pattern = rule.get("pattern", "")
        required = rule.get("required", False)
        prohibited = rule.get("prohibited", False)
        
        # Search for pattern
        found = bool(re.search(pattern, config, re.MULTILINE | re.IGNORECASE))
        
        # Determine pass/fail
        if required:
            passed = found
            message = f"Required pattern {'found' if found else 'NOT found'}: {pattern}"
        elif prohibited:
            passed = not found
            message = f"Prohibited pattern {'NOT found' if not found else 'FOUND'}: {pattern}"
        else:
            passed = True
            message = "Informational check"
        
        return ComplianceResult(
            device_name=device_name,
            rule_name=rule.get("name", "Unknown"),
            passed=passed,
            severity=rule.get("severity", "MEDIUM"),
            message=message,
            remediation=rule.get("remediation", "")
        )


# =============================================================================
# NOTIFICATION MANAGER
# =============================================================================

class NotificationManager:
    """Handles notifications (Slack, Email, etc.)"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
    
    def send_slack(self, message: str, webhook_url: str = None):
        """Send Slack notification"""
        import requests
        
        url = webhook_url or self.config.get("slack", {}).get("webhook_url") or os.getenv("SLACK_WEBHOOK")
        if not url:
            logger.debug("Slack webhook not configured")
            return
        
        try:
            payload = {"text": message}
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                logger.debug("📢 Slack notification sent")
            else:
                logger.warning(f"Slack notification failed: {response.status_code}")
        except Exception as e:
            logger.error(f"Slack notification error: {e}")
    
    def send_email(self, subject: str, body: str, recipients: List[str] = None):
        """Send email notification"""
        import smtplib
        from email.mime.text import MIMEText
        
        smtp_server = self.config.get("email", {}).get("smtp_server")
        if not smtp_server:
            logger.debug("Email not configured")
            return
        
        recipients = recipients or self.config.get("email", {}).get("recipients", [])
        
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.config.get("email", {}).get("from", "netbackup@company.com")
            msg["To"] = ", ".join(recipients)
            
            with smtplib.SMTP(smtp_server) as server:
                server.send_message(msg)
            
            logger.debug("📧 Email notification sent")
        except Exception as e:
            logger.error(f"Email notification error: {e}")


# =============================================================================
# MAIN BACKUP CLASS
# =============================================================================

class NetworkBackup:
    """Main network backup orchestrator"""
    
    def __init__(self, inventory: str = "inventory.yaml", backup_dir: str = "./backups",
                 git_enabled: bool = True, max_workers: int = 10):
        """
        Initialize network backup manager
        
        Args:
            inventory: Path to inventory YAML file
            backup_dir: Directory to store backups
            git_enabled: Enable Git versioning
            max_workers: Maximum parallel connections
        """
        self.inventory = InventoryManager(inventory)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        
        # Initialize Git manager
        self.git = GitManager(backup_dir) if git_enabled else None
        
        # Initialize compliance checker
        self.compliance = ComplianceChecker()
        
        # Initialize notifications
        self.notifications = NotificationManager()
    
    def backup_device(self, device_name: str) -> BackupResult:
        """
        Backup a single device
        
        Args:
            device_name: Device name from inventory
            
        Returns:
            BackupResult with backup status
        """
        device = self.inventory.get_device(device_name)
        if not device:
            return BackupResult(
                device_name=device_name,
                success=False,
                error=f"Device not found in inventory: {device_name}"
            )
        
        return self._backup_device(device)
    
    def _backup_device(self, device: Device) -> BackupResult:
        """Internal backup method"""
        start_time = datetime.now()
        
        connector = DeviceConnector(device)
        
        # Connect to device
        if not connector.connect():
            return BackupResult(
                device_name=device.name,
                success=False,
                error="Connection failed"
            )
        
        try:
            # Get configuration
            config = connector.get_config()
            
            if not config:
                return BackupResult(
                    device_name=device.name,
                    success=False,
                    error="Empty configuration returned"
                )
            
            # Determine output path
            output_dir = self.backup_dir
            if device.groups:
                output_dir = self.backup_dir / device.groups[0]
            output_dir.mkdir(parents=True, exist_ok=True)
            
            output_file = output_dir / f"{device.name}.cfg"
            
            # Check if configuration changed
            changed = True
            if output_file.exists():
                existing_config = output_file.read_text()
                changed = self._config_hash(config) != self._config_hash(existing_config)
            
            # Save configuration
            output_file.write_text(config)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return BackupResult(
                device_name=device.name,
                success=True,
                config=config,
                changed=changed,
                size_bytes=len(config.encode('utf-8')),
                duration_seconds=duration
            )
            
        except Exception as e:
            return BackupResult(
                device_name=device.name,
                success=False,
                error=str(e)
            )
            
        finally:
            connector.disconnect()
    
    def backup_all(self, commit: bool = True) -> List[BackupResult]:
        """
        Backup all devices in inventory
        
        Args:
            commit: Commit changes to Git after backup
            
        Returns:
            List of BackupResult for all devices
        """
        devices = self.inventory.get_all_devices()
        logger.info(f"🚀 Starting backup of {len(devices)} devices")
        
        results = []
        
        # Use ThreadPoolExecutor for parallel backups
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._backup_device, device): device for device in devices}
            
            for future in as_completed(futures):
                device = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    status = "✅" if result.success else "❌"
                    change = "Changed" if result.changed else "No Change"
                    logger.info(f"{status} {device.name}: {change}")
                    
                except Exception as e:
                    results.append(BackupResult(
                        device_name=device.name,
                        success=False,
                        error=str(e)
                    ))
        
        # Commit to Git
        if commit and self.git:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
            changed_count = sum(1 for r in results if r.changed)
            message = f"Automated backup {timestamp} - {changed_count} changes"
            self.git.commit_changes(message)
        
        # Print summary
        self._print_summary(results)
        
        return results
    
    def backup_group(self, group: str, commit: bool = True) -> List[BackupResult]:
        """Backup all devices in a group"""
        devices = self.inventory.get_devices_by_group(group)
        logger.info(f"🚀 Starting backup of {len(devices)} devices in group '{group}'")
        
        results = []
        for device in devices:
            result = self._backup_device(device)
            results.append(result)
        
        if commit and self.git:
            self.git.commit_changes(f"Backup group '{group}' - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        
        return results
    
    def diff_report(self, days: int = 7, device_name: str = None) -> Dict:
        """
        Generate configuration change report
        
        Args:
            days: Number of days to look back
            device_name: Specific device (or all if None)
            
        Returns:
            Report dictionary with changes
        """
        report = {
            "period_days": days,
            "generated": datetime.now().isoformat(),
            "devices": []
        }
        
        if not self.git or not self.git.repo:
            logger.warning("Git not available - cannot generate diff report")
            return report
        
        # Find all config files
        config_files = list(self.backup_dir.rglob("*.cfg"))
        
        for config_file in config_files:
            name = config_file.stem
            
            if device_name and name != device_name:
                continue
            
            # Get file path relative to repo
            rel_path = config_file.relative_to(self.backup_dir)
            
            # Get history
            history = self.git.get_file_history(str(rel_path), limit=50)
            
            # Filter by date
            cutoff = datetime.now() - timedelta(days=days)
            recent_history = [
                h for h in history
                if datetime.fromisoformat(h["date"].replace("Z", "+00:00")).replace(tzinfo=None) > cutoff
            ]
            
            if recent_history:
                report["devices"].append({
                    "name": name,
                    "changes": len(recent_history),
                    "history": recent_history
                })
        
        return report
    
    def check_compliance(self, rules_file: str, device_name: str = None) -> Dict:
        """
        Run compliance check against configurations
        
        Args:
            rules_file: Path to compliance rules YAML
            device_name: Specific device (or all if None)
            
        Returns:
            Compliance report
        """
        self.compliance = ComplianceChecker(rules_file)
        
        report = {
            "baseline": rules_file,
            "timestamp": datetime.now().isoformat(),
            "total_devices": 0,
            "compliant": 0,
            "non_compliant": 0,
            "findings": []
        }
        
        # Find all config files
        config_files = list(self.backup_dir.rglob("*.cfg"))
        
        for config_file in config_files:
            name = config_file.stem
            
            if device_name and name != device_name:
                continue
            
            config = config_file.read_text()
            results = self.compliance.check_config(name, config)
            
            report["total_devices"] += 1
            
            device_compliant = all(r.passed for r in results)
            if device_compliant:
                report["compliant"] += 1
            else:
                report["non_compliant"] += 1
            
            # Add failed checks to findings
            for result in results:
                if not result.passed:
                    report["findings"].append({
                        "device": result.device_name,
                        "rule": result.rule_name,
                        "severity": result.severity,
                        "message": result.message,
                        "remediation": result.remediation
                    })
        
        return report
    
    def _config_hash(self, config: str) -> str:
        """Generate hash of configuration for comparison"""
        # Remove timestamps and dynamic content
        cleaned = re.sub(r'!Time:.*', '', config)
        cleaned = re.sub(r'! Last configuration change.*', '', cleaned)
        cleaned = re.sub(r'ntp clock-period.*', '', cleaned)
        return hashlib.md5(cleaned.encode()).hexdigest()
    
    def _print_summary(self, results: List[BackupResult]):
        """Print backup summary"""
        success = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)
        changed = sum(1 for r in results if r.changed)
        
        print("\n" + "="*60)
        print("NETWORK CONFIGURATION BACKUP REPORT")
        print("="*60)
        print(f"Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Devices: {len(results)}")
        print(f"Successful:    {success}")
        print(f"Failed:        {failed}")
        print(f"Changed:       {changed}")
        print("="*60)
        
        for result in results:
            status = "✅" if result.success else "❌"
            size = f"{result.size_bytes/1024:.1f} KB" if result.success else result.error
            change = "Changed" if result.changed else "No Change"
            print(f"{status} {result.device_name:20} {size:15} {change}")
        
        print("="*60 + "\n")


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Network Configuration Backup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Backup all devices:
    python network_backup.py backup --all
    
  Backup specific device:
    python network_backup.py backup --device core-router-01
    
  Backup by group:
    python network_backup.py backup --group datacenter
    
  Show changes:
    python network_backup.py diff --days 7
    
  Compliance check:
    python network_backup.py compliance --rules rules/security.yaml

Author: Tamer Khalifa (CCIE #68867)
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Backup command
    backup_parser = subparsers.add_parser("backup", help="Backup device configurations")
    backup_parser.add_argument("--all", "-a", action="store_true", help="Backup all devices")
    backup_parser.add_argument("--device", "-d", help="Backup specific device")
    backup_parser.add_argument("--group", "-g", help="Backup devices in group")
    backup_parser.add_argument("--inventory", "-i", default="inventory.yaml", help="Inventory file")
    backup_parser.add_argument("--output", "-o", default="./backups", help="Backup directory")
    backup_parser.add_argument("--no-git", action="store_true", help="Disable Git versioning")
    backup_parser.add_argument("--workers", "-w", type=int, default=10, help="Parallel workers")
    
    # Diff command
    diff_parser = subparsers.add_parser("diff", help="Show configuration changes")
    diff_parser.add_argument("--days", "-d", type=int, default=7, help="Days to look back")
    diff_parser.add_argument("--device", help="Specific device")
    diff_parser.add_argument("--output", "-o", default="./backups", help="Backup directory")
    
    # Compliance command
    compliance_parser = subparsers.add_parser("compliance", help="Run compliance check")
    compliance_parser.add_argument("--rules", "-r", required=True, help="Compliance rules file")
    compliance_parser.add_argument("--device", "-d", help="Specific device")
    compliance_parser.add_argument("--output", "-o", default="./backups", help="Backup directory")
    compliance_parser.add_argument("--report", help="Output report file")
    
    # Schedule command
    schedule_parser = subparsers.add_parser("schedule", help="Run scheduled backups")
    schedule_parser.add_argument("--interval", "-i", default="6h", help="Backup interval (e.g., 6h, 30m)")
    schedule_parser.add_argument("--inventory", default="inventory.yaml", help="Inventory file")
    schedule_parser.add_argument("--output", "-o", default="./backups", help="Backup directory")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute commands
    if args.command == "backup":
        backup = NetworkBackup(
            inventory=args.inventory,
            backup_dir=args.output,
            git_enabled=not args.no_git,
            max_workers=args.workers
        )
        
        if args.all:
            backup.backup_all()
        elif args.device:
            result = backup.backup_device(args.device)
            print(f"{'✅' if result.success else '❌'} {result.device_name}: {'Success' if result.success else result.error}")
        elif args.group:
            backup.backup_group(args.group)
        else:
            print("Specify --all, --device, or --group")
            
    elif args.command == "diff":
        backup = NetworkBackup(backup_dir=args.output)
        report = backup.diff_report(days=args.days, device_name=args.device)
        
        print(f"\nConfiguration Changes (Last {args.days} Days)")
        print("="*60)
        for device in report["devices"]:
            print(f"\n📋 {device['name']}: {device['changes']} changes")
            for h in device["history"][:5]:
                print(f"   [{h['date'][:10]}] {h['message']}")
                
    elif args.command == "compliance":
        backup = NetworkBackup(backup_dir=args.output, git_enabled=False)
        report = backup.check_compliance(args.rules, args.device)
        
        print(f"\nCompliance Audit Report")
        print("="*60)
        print(f"Baseline:      {report['baseline']}")
        print(f"Total Devices: {report['total_devices']}")
        print(f"Compliant:     {report['compliant']} ({100*report['compliant']/max(report['total_devices'],1):.0f}%)")
        print(f"Non-Compliant: {report['non_compliant']}")
        print(f"\nFindings ({len(report['findings'])}):")
        
        for finding in report["findings"]:
            severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding["severity"], "⚪")
            print(f"  {severity_icon} [{finding['severity']}] {finding['device']}: {finding['rule']}")
            
        if args.report:
            with open(args.report, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📄 Report saved to: {args.report}")
            
    elif args.command == "schedule":
        import time
        import schedule as sched
        
        # Parse interval
        interval = args.interval
        if interval.endswith('h'):
            hours = int(interval[:-1])
            sched.every(hours).hours.do(lambda: NetworkBackup(inventory=args.inventory, backup_dir=args.output).backup_all())
        elif interval.endswith('m'):
            minutes = int(interval[:-1])
            sched.every(minutes).minutes.do(lambda: NetworkBackup(inventory=args.inventory, backup_dir=args.output).backup_all())
        
        print(f"📅 Scheduler started - backing up every {interval}")
        
        # Run initial backup
        NetworkBackup(inventory=args.inventory, backup_dir=args.output).backup_all()
        
        while True:
            sched.run_pending()
            time.sleep(60)


if __name__ == "__main__":
    main()
