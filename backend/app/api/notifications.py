from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.core.config import settings
from app.core.security import get_current_user
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/notifications", tags=["Notifications"])

# In-memory notification preferences (replace with DB-backed storage as needed)
_notification_settings: dict = {
    "slack_webhook_url": None,
    "notify_on_new_findings": True,
    "notify_on_scan_complete": True,
    "minimum_severity": "high",
}


class TestSlackRequest(BaseModel):
    webhook_url: Optional[str] = None


class NotificationConfigRequest(BaseModel):
    slack_webhook_url: Optional[str] = None
    notify_on_new_findings: Optional[bool] = None
    notify_on_scan_complete: Optional[bool] = None
    minimum_severity: Optional[str] = None


@router.post("/test-slack")
async def test_slack_notification(
    body: TestSlackRequest = TestSlackRequest(),
    current_user=Depends(get_current_user),
):
    """Send a test message to verify Slack webhook connectivity."""
    webhook_url = body.webhook_url or _notification_settings.get("slack_webhook_url") or settings.SLACK_WEBHOOK_URL
    if not webhook_url:
        raise HTTPException(
            status_code=400,
            detail="No Slack webhook URL provided or configured",
        )

    service = NotificationService()
    success = await service.send_test_notification(webhook_url=webhook_url)
    if not success:
        raise HTTPException(status_code=502, detail="Failed to send Slack test notification")

    return {"message": "Test notification sent successfully"}


@router.post("/configure")
async def configure_notifications(
    body: NotificationConfigRequest,
    current_user=Depends(get_current_user),
):
    """Save notification preferences."""
    if body.slack_webhook_url is not None:
        _notification_settings["slack_webhook_url"] = body.slack_webhook_url
    if body.notify_on_new_findings is not None:
        _notification_settings["notify_on_new_findings"] = body.notify_on_new_findings
    if body.notify_on_scan_complete is not None:
        _notification_settings["notify_on_scan_complete"] = body.notify_on_scan_complete
    if body.minimum_severity is not None:
        _notification_settings["minimum_severity"] = body.minimum_severity

    return {"message": "Notification settings updated", "settings": _notification_settings}


@router.get("/settings")
async def get_notification_settings(
    current_user=Depends(get_current_user),
):
    """Return current notification preferences."""
    return {
        "slack_webhook_url": _notification_settings.get("slack_webhook_url") or settings.SLACK_WEBHOOK_URL,
        "notify_on_new_findings": _notification_settings["notify_on_new_findings"],
        "notify_on_scan_complete": _notification_settings["notify_on_scan_complete"],
        "minimum_severity": _notification_settings["minimum_severity"],
        "slack_configured": bool(
            _notification_settings.get("slack_webhook_url") or settings.SLACK_WEBHOOK_URL
        ),
    }
