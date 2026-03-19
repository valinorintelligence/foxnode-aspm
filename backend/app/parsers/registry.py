from typing import Optional


class BaseParser:
    name: str = ""
    scan_type: str = ""
    description: str = ""

    def parse(self, content: bytes) -> list[dict]:
        raise NotImplementedError


class ParserRegistry:
    _parsers: dict[str, BaseParser] = {}

    @classmethod
    def register(cls, parser: BaseParser):
        cls._parsers[parser.name.lower()] = parser

    @classmethod
    def get_parser(cls, name: str) -> Optional[BaseParser]:
        return cls._parsers.get(name.lower())

    @classmethod
    def list_parsers(cls) -> list[dict]:
        return [
            {"name": p.name, "scan_type": p.scan_type, "description": p.description}
            for p in cls._parsers.values()
        ]


# Import and register all parsers
from app.parsers.trivy import TrivyParser
from app.parsers.semgrep import SemgrepParser
from app.parsers.snyk import SnykParser
from app.parsers.gitleaks import GitleaksParser
from app.parsers.bandit import BanditParser
from app.parsers.zap import ZapParser
from app.parsers.nuclei import NucleiParser
from app.parsers.generic import GenericParser
from app.parsers.checkov import CheckovParser
from app.parsers.sonarqube import SonarQubeParser
from app.parsers.dependency_check import DependencyCheckParser
from app.parsers.prowler import ProwlerParser
from app.parsers.tfsec import TfsecParser
from app.parsers.trufflehog import TruffleHogParser
from app.parsers.sarif import SarifParser

ParserRegistry.register(TrivyParser())
ParserRegistry.register(SemgrepParser())
ParserRegistry.register(SnykParser())
ParserRegistry.register(GitleaksParser())
ParserRegistry.register(BanditParser())
ParserRegistry.register(ZapParser())
ParserRegistry.register(NucleiParser())
ParserRegistry.register(GenericParser())
ParserRegistry.register(CheckovParser())
ParserRegistry.register(SonarQubeParser())
ParserRegistry.register(DependencyCheckParser())
ParserRegistry.register(ProwlerParser())
ParserRegistry.register(TfsecParser())
ParserRegistry.register(TruffleHogParser())
ParserRegistry.register(SarifParser())
