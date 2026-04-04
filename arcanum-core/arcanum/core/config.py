"""Arcanum Core configuration with model tier auto-detection."""

from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings


# ---------------------------------------------------------------------------
# Model tier recommendations based on available VRAM
# ---------------------------------------------------------------------------

MODEL_TIERS = [
    {"tier": "small",  "min_ram_gb": 8,  "max_ram_gb": 16,  "model": "qwen3:30b-a3b",  "params": "30B (3B active MoE)", "ctx": 32768},
    {"tier": "medium", "min_ram_gb": 16, "max_ram_gb": 64,  "model": "qwen3:32b",       "params": "32B",                 "ctx": 131072},
    {"tier": "large",  "min_ram_gb": 64, "max_ram_gb": 192, "model": "qwen3.5:122b",    "params": "122B (10B active MoE)","ctx": 131072},
    {"tier": "xlarge", "min_ram_gb": 192,"max_ram_gb": 999, "model": "qwen3.5:400b",    "params": "397B (17B active MoE)","ctx": 131072},
]


def detect_system_memory_gb() -> int:
    """Detect available system RAM in GB."""
    try:
        import psutil
        return int(psutil.virtual_memory().total / (1024 ** 3))
    except ImportError:
        pass
    try:
        import subprocess
        result = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return int(int(result.stdout.strip()) / (1024 ** 3))
    except Exception:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    return int(int(line.split()[1]) / (1024 ** 2))
    except Exception:
        pass
    return 16  # Default assumption


def recommend_model_tier(ram_gb: int = None) -> dict:
    """Recommend a model tier based on available RAM."""
    if ram_gb is None:
        ram_gb = detect_system_memory_gb()
    for tier in reversed(MODEL_TIERS):
        if ram_gb >= tier["min_ram_gb"]:
            return {**tier, "detected_ram_gb": ram_gb}
    return {**MODEL_TIERS[0], "detected_ram_gb": ram_gb}


class ArcanumConfig(BaseSettings):
    """Central configuration for the Arcanum platform."""

    model_config = {"env_prefix": "ARCANUM_"}

    # Ollama / LLM
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:32b"
    ollama_timeout: float = 300.0
    ollama_chunk_timeout: float = 180.0
    ollama_num_ctx: int = 131072
    ollama_temperature: float = 0.15
    ollama_num_predict: int = 32768
    ollama_enable_thinking: bool = True
    ollama_repeat_penalty: float = 1.05

    # Sandbox
    sandbox_image: str = "arcanum-sandbox:latest"
    sandbox_timeout: int = 300
    command_timeout: int = 900

    # Data paths
    data_dir: Path = Path.home() / ".arcanum"

    # Web server
    web_port: int = 8000
    web_host: str = "0.0.0.0"

    # Agent
    max_context_tokens: int = 32000
    deep_recon_autostart: bool = True
    allow_destructive_testing: bool = False
    vuln_similarity_threshold: float = 0.7

    # Logging
    log_level: str = "INFO"

    @property
    def ops_dir(self) -> Path:
        return self.data_dir / "ops"

    @property
    def stash_db(self) -> Path:
        return self.data_dir / "stash.db"

    @property
    def cve_db(self) -> Path:
        return self.data_dir / "cve.db"

    @property
    def sessions_db(self) -> Path:
        return self.data_dir / "arcanum.db"

    @property
    def workflows_dir(self) -> Path:
        return self.data_dir / "workflows"

    def model_post_init(self, __context) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.ops_dir.mkdir(parents=True, exist_ok=True)
        self.workflows_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_config() -> ArcanumConfig:
    """Return the singleton ArcanumConfig instance."""
    return ArcanumConfig()
