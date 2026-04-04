"""Copilot mode - AI suggests, user approves."""
from rich.console import Console

console = Console()


class CopilotRunner:
    """AI suggests actions with risk assessment, user approves each."""

    def __init__(self, engine, target: str):
        self.engine = engine
        self.target = target
        self.pending_suggestion = None

    async def run(self, user_input: str):
        """Process user input in copilot mode."""
        prompt = f"""You are in COPILOT mode assessing {self.target}.
The user said: {user_input}

For each action you want to take:
1. Describe what you want to do
2. Rate the risk level (LOW/MEDIUM/HIGH)
3. Estimate duration
4. Classify stealth (Passive/Active)
5. Wait for user approval before executing

Always explain WHY you're suggesting each action."""

        async for event in self.engine.run(prompt):
            yield event

    async def approve(self):
        """Approve pending suggestion."""
        if self.pending_suggestion:
            async for event in self.engine.run("Yes, proceed with the suggested action."):
                yield event
            self.pending_suggestion = None

    async def modify(self, modification: str):
        """Modify and execute pending suggestion."""
        if self.pending_suggestion:
            async for event in self.engine.run(f"Modify the suggestion: {modification}"):
                yield event
            self.pending_suggestion = None
