import logging
from typing import Any, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFAA00",
    "low": "#36A64F",
    "info": "#439FE0",
}


class NotificationService:
    """Service for sending notifications via Slack and other channels."""

    async def send_slack_notification(
        self, webhook_url: str, message: dict[str, Any]
    ) -> bool:
        """Send a message payload to a Slack incoming webhook.

        Args:
            webhook_url: The Slack incoming webhook URL.
            message: Slack message payload (text and/or blocks).

        Returns:
            True if the message was sent successfully, False otherwise.
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(webhook_url, json=message)
                response.raise_for_status()
                logger.info("Slack notification sent successfully")
                return True
        except httpx.HTTPStatusError as exc:
            logger.error("Slack webhook returned HTTP %s", exc.response.status_code)
            return False
        except httpx.RequestError as exc:
            logger.error("Slack webhook request failed: %s", exc)
            return False

    async def notify_new_findings(
        self,
        product_name: str,
        findings_count: int,
        critical_count: int,
        high_count: int,
        webhook_url: Optional[str] = None,
    ) -> bool:
        """Send a Slack notification about newly discovered findings.

        Args:
            product_name: Name of the product/application.
            findings_count: Total number of new findings.
            critical_count: Number of critical-severity findings.
            high_count: Number of high-severity findings.
            webhook_url: Override Slack webhook URL (falls back to settings).

        Returns:
            True if sent successfully.
        """
        url = webhook_url or settings.SLACK_WEBHOOK_URL
        if not url:
            logger.warning("No Slack webhook URL configured; skipping notification")
            return False

        severity_lines = []
        if critical_count > 0:
            severity_lines.append(f":red_circle: *Critical:* {critical_count}")
        if high_count > 0:
            severity_lines.append(f":large_orange_circle: *High:* {high_count}")
        other_count = findings_count - critical_count - high_count
        if other_count > 0:
            severity_lines.append(f":large_yellow_circle: *Medium/Low/Info:* {other_count}")

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":shield: New Security Findings Detected",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Product:*\n{product_name}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Findings:*\n{findings_count}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Severity Breakdown:*\n" + "\n".join(severity_lines),
                },
            },
            {"type": "divider"},
        ]

        message = {"blocks": blocks}
        return await self.send_slack_notification(url, message)

    async def notify_scan_complete(
        self,
        scan_import: Any,
        webhook_url: Optional[str] = None,
    ) -> bool:
        """Send a Slack notification when a scan import finishes.

        Args:
            scan_import: ScanImport model instance.
            webhook_url: Override Slack webhook URL (falls back to settings).

        Returns:
            True if sent successfully.
        """
        url = webhook_url or settings.SLACK_WEBHOOK_URL
        if not url:
            logger.warning("No Slack webhook URL configured; skipping notification")
            return False

        status_emoji = ":white_check_mark:" if scan_import.status == "completed" else ":x:"

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Scan Import {scan_import.status.capitalize()}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Scanner:*\n{scan_import.scanner}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*File:*\n{scan_import.filename}",
                    },
                ],
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Findings Created:*\n{scan_import.findings_created}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Duplicates:*\n{scan_import.findings_duplicates}",
                    },
                ],
            },
        ]

        if scan_import.error_message:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Error:*\n```{scan_import.error_message}```",
                    },
                }
            )

        blocks.append({"type": "divider"})
        message = {"blocks": blocks}
        return await self.send_slack_notification(url, message)

    async def send_test_notification(
        self, webhook_url: Optional[str] = None
    ) -> bool:
        """Send a test notification to verify Slack webhook connectivity.

        Args:
            webhook_url: Override Slack webhook URL (falls back to settings).

        Returns:
            True if sent successfully.
        """
        url = webhook_url or settings.SLACK_WEBHOOK_URL
        if not url:
            return False

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":white_check_mark: Foxnode ASPM - Test Notification",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "This is a test notification from *Foxnode ASPM*. If you see this message, your Slack integration is working correctly.",
                },
            },
            {"type": "divider"},
        ]

        message = {"blocks": blocks}
        return await self.send_slack_notification(url, message)
