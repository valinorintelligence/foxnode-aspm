"""Real-time alert engine for critical findings."""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Awaitable


class AlertPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Alert:
    id: str
    priority: AlertPriority
    title: str
    description: str
    source: str
    finding_id: str | None = None
    acknowledged: bool = False


@dataclass
class AlertRule:
    name: str
    pattern: str
    priority: AlertPriority
    description: str


class AlertEngine:
    """Monitors tool output and findings for critical patterns."""

    DEFAULT_RULES = [
        AlertRule("critical_cve", r"CVE-\d{4}-\d+.*(?:critical|9\.\d)", AlertPriority.CRITICAL, "Critical CVE detected"),
        AlertRule("rce_detected", r"(?:remote code execution|RCE|command injection)", AlertPriority.CRITICAL, "RCE vulnerability found"),
        AlertRule("sqli_confirmed", r"(?:SQL injection|SQLi).*(?:confirmed|verified|exploitable)", AlertPriority.CRITICAL, "SQL injection confirmed"),
        AlertRule("credentials_found", r"(?:password|credential|secret|token|api.?key)\s*[:=]", AlertPriority.HIGH, "Credentials discovered"),
        AlertRule("admin_panel", r"(?:admin|dashboard|management)\s*(?:panel|console|interface)", AlertPriority.MEDIUM, "Admin panel discovered"),
        AlertRule("default_creds", r"(?:default|weak)\s*(?:password|credential)", AlertPriority.HIGH, "Default credentials found"),
        AlertRule("xss_confirmed", r"(?:XSS|cross.?site.?scripting).*(?:confirmed|reflected|stored)", AlertPriority.HIGH, "XSS vulnerability confirmed"),
    ]

    def __init__(self):
        self.rules: list[AlertRule] = list(self.DEFAULT_RULES)
        self.alerts: list[Alert] = []
        self._handlers: list[Callable[[Alert], Awaitable[None]]] = []
        self._alert_counter = 0

    def on_alert(self, handler: Callable[[Alert], Awaitable[None]]):
        self._handlers.append(handler)

    async def scan_output(self, text: str, source: str = "tool") -> list[Alert]:
        new_alerts = []
        for rule in self.rules:
            if re.search(rule.pattern, text, re.IGNORECASE):
                self._alert_counter += 1
                alert = Alert(
                    id=f"alert-{self._alert_counter:04d}",
                    priority=rule.priority,
                    title=rule.description,
                    description=f"Pattern '{rule.name}' matched in {source} output",
                    source=source,
                )
                self.alerts.append(alert)
                new_alerts.append(alert)
                for handler in self._handlers:
                    await handler(alert)
        return new_alerts

    async def scan_finding(self, finding_data: dict) -> list[Alert]:
        severity = finding_data.get("severity", "").lower()
        if severity in ("critical", "high"):
            self._alert_counter += 1
            alert = Alert(
                id=f"alert-{self._alert_counter:04d}",
                priority=AlertPriority.CRITICAL if severity == "critical" else AlertPriority.HIGH,
                title=f"{severity.upper()}: {finding_data.get('title', 'Unknown')}",
                description=f"New {severity} finding created",
                source="finding",
                finding_id=finding_data.get("id"),
            )
            self.alerts.append(alert)
            for handler in self._handlers:
                await handler(alert)
            return [alert]
        return []

    def get_unacknowledged(self) -> list[Alert]:
        return [a for a in self.alerts if not a.acknowledged]

    def acknowledge(self, alert_id: str) -> bool:
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                return True
        return False
