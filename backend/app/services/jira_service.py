import logging
from typing import Any, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_PRIORITY_MAP = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Low",
}


class JiraService:
    """Service for integrating with Jira issue tracking."""

    def __init__(
        self,
        url: Optional[str] = None,
        username: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        self.url = (url or settings.JIRA_URL or "").rstrip("/")
        self.username = username or settings.JIRA_USERNAME
        self.api_token = api_token or settings.JIRA_API_TOKEN
        self._auth = (self.username, self.api_token) if self.username and self.api_token else None

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Make an authenticated request to the Jira REST API."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method,
                f"{self.url}/rest/api/2{path}",
                headers=self._headers(),
                auth=self._auth,
                **kwargs,
            )
            response.raise_for_status()
            return response.json()

    async def create_issue(
        self,
        finding: Any,
        project_key: str = "SEC",
        issue_type: str = "Bug",
    ) -> dict[str, Any]:
        """Create a Jira issue from a Finding object.

        Args:
            finding: Finding model instance with title, description, severity, etc.
            project_key: Jira project key to create the issue in.
            issue_type: Jira issue type name (e.g. Bug, Task, Story).

        Returns:
            Jira API response containing the created issue key and id.
        """
        severity_value = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        )
        priority_name = SEVERITY_PRIORITY_MAP.get(severity_value, "Medium")

        labels = ["security", f"severity-{severity_value}"]
        if finding.scanner:
            labels.append(f"scanner-{finding.scanner}")
        if finding.cve:
            labels.append(finding.cve)

        description_parts = []
        if finding.description:
            description_parts.append(finding.description)
        if finding.file_path:
            description_parts.append(f"\n*File:* {finding.file_path}")
            if finding.line_number:
                description_parts[-1] += f" (line {finding.line_number})"
        if finding.cve:
            description_parts.append(f"*CVE:* {finding.cve}")
        if finding.cwe:
            description_parts.append(f"*CWE:* CWE-{finding.cwe}")
        if finding.cvss_score is not None:
            description_parts.append(f"*CVSS Score:* {finding.cvss_score}")
        if finding.mitigation:
            description_parts.append(f"\n*Recommended Mitigation:*\n{finding.mitigation}")

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": finding.title,
                "description": "\n".join(description_parts),
                "issuetype": {"name": issue_type},
                "priority": {"name": priority_name},
                "labels": labels,
            }
        }

        logger.info("Creating Jira issue for finding %s in project %s", finding.id, project_key)
        result = await self._request("POST", "/issue", json=payload)
        logger.info("Created Jira issue %s", result.get("key"))
        return result

    async def sync_status(
        self, finding_id: int, jira_key: str
    ) -> dict[str, Any]:
        """Fetch the current status of a Jira issue.

        Args:
            finding_id: The local finding ID (for logging context).
            jira_key: The Jira issue key (e.g. SEC-123).

        Returns:
            Dict with jira_key, status name, and full status category info.
        """
        logger.info("Syncing Jira status for finding %s (Jira: %s)", finding_id, jira_key)
        data = await self._request("GET", f"/issue/{jira_key}", params={"fields": "status"})
        status_info = data.get("fields", {}).get("status", {})
        return {
            "jira_key": jira_key,
            "status": status_info.get("name"),
            "status_category": status_info.get("statusCategory", {}).get("name"),
        }

    async def search_issues(self, jql: str, max_results: int = 50) -> dict[str, Any]:
        """Search Jira issues using JQL.

        Args:
            jql: JQL query string.
            max_results: Maximum number of results to return.

        Returns:
            Jira search API response with matching issues.
        """
        payload = {
            "jql": jql,
            "maxResults": max_results,
            "fields": ["summary", "status", "priority", "labels", "created", "updated"],
        }
        return await self._request("POST", "/search", json=payload)

    async def check_connection(self) -> dict[str, Any]:
        """Verify that the Jira connection is working.

        Returns:
            Dict with connected status and server info or error message.
        """
        if not self.url or not self._auth:
            return {"connected": False, "error": "Jira credentials not configured"}
        try:
            data = await self._request("GET", "/serverInfo")
            return {
                "connected": True,
                "server_title": data.get("serverTitle"),
                "version": data.get("version"),
                "base_url": self.url,
            }
        except httpx.HTTPStatusError as exc:
            logger.warning("Jira connection failed: %s", exc)
            return {"connected": False, "error": f"HTTP {exc.response.status_code}"}
        except httpx.RequestError as exc:
            logger.warning("Jira connection error: %s", exc)
            return {"connected": False, "error": str(exc)}
