"""Arcanum Core - Textual TUI Application."""
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Input, RichLog, TabbedContent, TabPane, DataTable, Label
from textual.binding import Binding
from textual.reactive import reactive

from ..core.models import Mode


TOOL_TABS = ["Recon", "Web", "Network", "Creds", "Exploit", "Post", "OSINT", "Findings"]


class StatusBar(Static):
    """Top status bar showing op info."""

    op_name = reactive("No Op")
    mode = reactive("MANUAL")
    llm_status = reactive("Offline")

    def render(self) -> str:
        return f" ARCANUM CORE v3.0.0  │  Op: {self.op_name}  │  Mode: {self.mode}  │  LLM: {self.llm_status}"


class OutputLog(RichLog):
    """Main output panel for tool results and AI responses."""
    pass


class FindingsPanel(Static):
    """Right panel showing current findings."""

    findings: reactive[list] = reactive(list)

    def render(self) -> str:
        if not self.findings:
            return "FINDINGS (0)\n─────────────────\nNo findings yet."
        lines = [f"FINDINGS ({len(self.findings)})", "─────────────────"]
        severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for f in self.findings[:15]:
            icon = severity_icons.get(f.get("severity", "info"), "⚪")
            lines.append(f"{icon} {f.get('title', 'Unknown')[:35]}")
        return "\n".join(lines)


class StashPanel(Static):
    """Panel showing stash items."""

    items: reactive[list] = reactive(list)

    def render(self) -> str:
        if not self.items:
            return "STASH (0)\n─────────────────\nNo items."
        lines = [f"STASH ({len(self.items)})", "─────────────────"]
        for item in self.items[:10]:
            lines.append(f"📋 {item.get('value', '')[:30]} ({item.get('type', '')})")
        return "\n".join(lines)


class CommandInput(Input):
    """Bottom command input."""
    pass


class ArcanumApp(App):
    """The Arcanum Core TUI application."""

    TITLE = "Arcanum Core"
    CSS = """
    Screen {
        layout: grid;
        grid-size: 1;
        grid-rows: 3 1fr 3;
    }

    #status-bar {
        dock: top;
        height: 3;
        background: $primary-darken-3;
        color: $text;
        padding: 1;
    }

    #main-container {
        layout: grid;
        grid-size: 2 1;
        grid-columns: 3fr 1fr;
    }

    #left-panel {
        height: 100%;
    }

    #right-panel {
        height: 100%;
        border-left: solid $primary;
        padding: 1;
    }

    #output-log {
        height: 1fr;
        border: solid $primary;
        margin: 0 1;
    }

    #command-input {
        dock: bottom;
        margin: 0 1;
    }

    #findings-panel {
        height: 1fr;
    }

    #stash-panel {
        height: auto;
        margin-top: 1;
    }

    TabPane {
        padding: 1;
    }
    """

    BINDINGS = [
        Binding("f1", "help", "Help"),
        Binding("f2", "workspace", "Workspace"),
        Binding("f3", "stash", "Stash"),
        Binding("f4", "cve_search", "CVE"),
        Binding("f5", "switch_mode", "Mode"),
        Binding("f9", "generate_report", "Report"),
        Binding("f10", "quit", "Quit"),
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, mode: str = "manual", target: str = None, op_name: str = None):
        super().__init__()
        self.current_mode = mode
        self.target = target
        self.op_name = op_name or "default"
        self._engine = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatusBar(id="status-bar")
        with Container(id="main-container"):
            with Vertical(id="left-panel"):
                with TabbedContent(*TOOL_TABS):
                    for tab in TOOL_TABS:
                        with TabPane(tab, id=f"tab-{tab.lower()}"):
                            yield Static(f"{tab} tools panel - ready", classes="tab-content")
                yield OutputLog(id="output-log", highlight=True, markup=True)
            with Vertical(id="right-panel"):
                yield FindingsPanel(id="findings-panel")
                yield StashPanel(id="stash-panel")
        yield CommandInput(placeholder="> Enter command or ask a question...", id="command-input")
        yield Footer()

    def on_mount(self) -> None:
        status = self.query_one("#status-bar", StatusBar)
        status.op_name = self.op_name
        status.mode = self.current_mode.upper()
        log = self.query_one("#output-log", OutputLog)
        log.write(f"[bold green]Arcanum Core v3.0.0[/]")
        log.write(f"Mode: [bold]{self.current_mode.upper()}[/]")
        if self.target:
            log.write(f"Target: [bold cyan]{self.target}[/]")
        log.write("Type a command or question below. Press F1 for help.")
        log.write("")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        user_input = event.value.strip()
        if not user_input:
            return
        input_widget = self.query_one("#command-input", CommandInput)
        input_widget.value = ""
        log = self.query_one("#output-log", OutputLog)
        log.write(f"\n[bold white]> {user_input}[/]")

        # Handle built-in commands
        if user_input.lower() in ("quit", "exit"):
            self.exit()
            return
        if user_input.lower() == "help":
            self._show_help(log)
            return
        if user_input.lower().startswith("mode "):
            new_mode = user_input.split(" ", 1)[1].strip().lower()
            if new_mode in ("autopilot", "copilot", "manual"):
                self.current_mode = new_mode
                self.query_one("#status-bar", StatusBar).mode = new_mode.upper()
                log.write(f"[green]Switched to {new_mode.upper()} mode[/]")
            else:
                log.write(f"[red]Unknown mode: {new_mode}. Use: autopilot, copilot, manual[/]")
            return

        # Process through agent engine
        log.write(f"[dim]Processing in {self.current_mode} mode...[/]")
        if self._engine:
            try:
                async for event in self._engine.run(user_input):
                    self._handle_event(event, log)
            except Exception as e:
                log.write(f"[red]Error: {e}[/]")
        else:
            log.write("[yellow]Agent engine not connected. Ensure Ollama is running.[/]")
            log.write(f"[dim]Would process: '{user_input}' in {self.current_mode} mode[/]")

    def _handle_event(self, event: dict, log: OutputLog):
        etype = event.get("type", "")
        if etype == "thinking":
            log.write(f"[dim italic]{event.get('content', '')}[/]")
        elif etype == "tool_call":
            log.write(f"[cyan][TOOL] {event.get('name', '')}: {event.get('arguments', {})}[/]")
        elif etype == "tool_result":
            result = event.get("result", "")
            log.write(f"[green][RESULT] {str(result)[:500]}[/]")
        elif etype == "suggestion":
            log.write(f"[yellow][SUGGEST] {event.get('description', '')}[/]")
            log.write(f"[yellow]Risk: {event.get('risk', 'UNKNOWN')} | [Y]es / [N]o / [M]odify?[/]")
        elif etype == "response":
            log.write(f"\n{event.get('content', '')}")
        elif etype == "finding":
            log.write(f"[bold red][FINDING] {event.get('title', '')} - {event.get('severity', '')}[/]")
        elif etype == "error":
            log.write(f"[red][ERROR] {event.get('message', '')}[/]")

    def _show_help(self, log: OutputLog):
        log.write("""[bold]Arcanum Core - Help[/]
[bold]Commands:[/]
  mode <autopilot|copilot|manual>  Switch interaction mode
  help                              Show this help
  quit / exit                       Exit application

[bold]Keyboard Shortcuts:[/]
  F1  Help       F2  Workspace   F3  Stash
  F4  CVE Search F5  Switch Mode F9  Report
  F10 Quit       Esc Cancel

[bold]In Autopilot:[/] Give a target, AI runs full assessment
[bold]In Copilot:[/] AI suggests actions, you approve each
[bold]In Manual:[/] You run commands, AI advises""")

    def action_help(self) -> None:
        log = self.query_one("#output-log", OutputLog)
        self._show_help(log)

    def action_switch_mode(self) -> None:
        modes = ["manual", "copilot", "autopilot"]
        current_idx = modes.index(self.current_mode) if self.current_mode in modes else 0
        self.current_mode = modes[(current_idx + 1) % len(modes)]
        self.query_one("#status-bar", StatusBar).mode = self.current_mode.upper()
        log = self.query_one("#output-log", OutputLog)
        log.write(f"[green]Switched to {self.current_mode.upper()} mode[/]")

    def action_generate_report(self) -> None:
        log = self.query_one("#output-log", OutputLog)
        log.write("[yellow]Generating report...[/]")

    def action_workspace(self) -> None:
        log = self.query_one("#output-log", OutputLog)
        log.write("[cyan]Workspace explorer - coming soon[/]")

    def action_stash(self) -> None:
        log = self.query_one("#output-log", OutputLog)
        log.write("[cyan]Stash manager - use 'arcanum stash list' in CLI[/]")

    def action_cve_search(self) -> None:
        log = self.query_one("#output-log", OutputLog)
        log.write("[cyan]CVE Search - type 'cve <query>' to search[/]")

    def action_cancel(self) -> None:
        pass
