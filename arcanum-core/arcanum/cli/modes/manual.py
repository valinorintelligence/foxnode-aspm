"""Manual mode - user drives, AI advises."""
from rich.console import Console

console = Console()


class ManualRunner:
    """User runs commands directly, AI provides guidance on request."""

    def __init__(self, engine, target: str = None):
        self.engine = engine
        self.target = target

    async def run(self, user_input: str):
        """Process user input in manual mode."""
        # Check if it's a direct command (starts with 'run ')
        if user_input.lower().startswith("run "):
            command = user_input[4:].strip()
            prompt = f"Execute this command in the sandbox: {command}"
        else:
            # Treat as a question/request for advice
            context = f" for target {self.target}" if self.target else ""
            prompt = f"""You are in MANUAL mode{context}. The user is driving the assessment.
Provide expert advice and guidance. Do NOT execute any tools unless the user explicitly asks.

User message: {user_input}"""

        async for event in self.engine.run(prompt):
            yield event
