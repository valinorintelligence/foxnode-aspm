"""Browser automation for web application security testing."""

from __future__ import annotations

from typing import Any


class BrowserAutomation:
    """Headless browser automation using Playwright for web security testing."""

    def __init__(self) -> None:
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    async def start(self) -> None:
        """Launch a headless Chromium browser via Playwright."""
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)
        self._context = await self._browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        self._page = await self._context.new_page()

    async def navigate(self, url: str) -> dict:
        """Navigate to a URL and return page metadata.

        Args:
            url: The target URL to navigate to.

        Returns:
            Dict with 'url', 'title', and 'status' keys.
        """
        response = await self._page.goto(url, wait_until="domcontentloaded")
        return {
            "url": self._page.url,
            "title": await self._page.title(),
            "status": response.status if response else None,
        }

    async def click(self, selector: str) -> dict:
        """Click an element matching the CSS selector.

        Args:
            selector: CSS selector for the target element.

        Returns:
            Dict with 'selector' and 'success' keys.
        """
        await self._page.click(selector)
        return {"selector": selector, "success": True}

    async def type_text(self, selector: str, text: str) -> dict:
        """Type text into an input element.

        Args:
            selector: CSS selector for the input element.
            text: Text to type into the element.

        Returns:
            Dict with 'selector', 'text', and 'success' keys.
        """
        await self._page.fill(selector, text)
        return {"selector": selector, "text": text, "success": True}

    async def screenshot(self, path: str) -> dict:
        """Capture a screenshot of the current page.

        Args:
            path: File path to save the screenshot.

        Returns:
            Dict with 'path' and 'success' keys.
        """
        await self._page.screenshot(path=path, full_page=True)
        return {"path": path, "success": True}

    async def get_text(self, selector: str) -> str:
        """Get the text content of an element.

        Args:
            selector: CSS selector for the target element.

        Returns:
            The text content of the matched element.
        """
        element = await self._page.query_selector(selector)
        if element is None:
            return ""
        return await element.text_content() or ""

    async def get_page_source(self) -> str:
        """Get the full HTML source of the current page.

        Returns:
            The page HTML as a string.
        """
        return await self._page.content()

    async def close(self) -> None:
        """Close the browser and clean up resources."""
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if hasattr(self, "_playwright") and self._playwright:
            await self._playwright.stop()
        self._browser = None
        self._context = None
        self._page = None
