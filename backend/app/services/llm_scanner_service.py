"""LLM-aware vulnerability scanning engine.

Identifies AI/ML-specific vulnerabilities that traditional SAST tools miss
using pure pattern matching and heuristic analysis — no external API calls.
"""

import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.product import Product

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityMatch:
    vulnerability_type: str
    severity: str
    confidence: str  # "high", "medium", "low"
    description: str
    line_number: int
    recommendation: str
    cwe_id: int
    owasp_category: str  # OWASP LLM Top 10 code (e.g. "LLM01")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AIRiskAssessment:
    product_id: int
    ai_exposure_level: str  # "none", "low", "medium", "high", "critical"
    prompt_injection_risk: str
    data_poisoning_risk: str
    model_supply_chain_risk: str
    total_ai_findings: int
    severity_breakdown: dict[str, int]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Vulnerability pattern definitions
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityPattern:
    """A regex-based detection rule for AI/ML vulnerabilities."""
    name: str
    pattern: re.Pattern
    severity: str
    description: str
    recommendation: str
    cwe_id: int
    owasp_category: str
    confidence: str = "medium"
    languages: list[str] = field(default_factory=lambda: ["python", "javascript", "typescript"])


# All patterns compiled once at module load
VULNERABILITY_PATTERNS: list[VulnerabilityPattern] = [
    # ---- Prompt Injection (Direct) ----
    VulnerabilityPattern(
        name="Prompt Injection — Direct User Input in Prompt",
        pattern=re.compile(
            r"""(?:f["'].*\{.*(?:user_input|user_message|request\.body|req\.body"""
            r"""|query|prompt|input_text|user_query).*\}"""
            r"""|\.format\(.*(?:user_input|user_message|query|prompt|input_text)"""
            r"""|%\s*(?:user_input|user_message|query|prompt|input_text)"""
            r"""|(?:messages|prompt)\s*(?:\+|\.append|\.extend).*(?:user_input|request|req\.|input))""",
            re.IGNORECASE,
        ),
        severity="critical",
        description=(
            "User-controlled input is interpolated directly into an LLM prompt "
            "without sanitization. An attacker can craft input that overrides "
            "system instructions, exfiltrates data, or triggers unintended actions."
        ),
        recommendation=(
            "Separate system instructions from user content using distinct message "
            "roles. Apply input validation, length limits, and output filtering. "
            "Consider using prompt templating libraries with built-in escaping."
        ),
        cwe_id=77,
        owasp_category="LLM01",
        confidence="high",
    ),
    VulnerabilityPattern(
        name="Prompt Injection — Indirect via External Data",
        pattern=re.compile(
            r"""(?:(?:fetch|requests\.get|urllib|httpx|axios).*(?:then|\.text|\.json).*(?:prompt|messages|completion)"""
            r"""|(?:read_file|open\(|readFileSync|readFile).*(?:prompt|messages|completion)"""
            r"""|(?:database|db|cursor|query).*(?:prompt|messages|completion)"""
            r"""|(?:scrape|crawl|parse_html|BeautifulSoup).*(?:prompt|messages))""",
            re.IGNORECASE,
        ),
        severity="high",
        description=(
            "External data (web content, files, database records) is fed into an "
            "LLM prompt. Attackers can embed malicious instructions in these sources "
            "to hijack the model's behavior (indirect prompt injection)."
        ),
        recommendation=(
            "Treat all external data as untrusted. Summarize or sanitize content "
            "before including it in prompts. Implement output validation and "
            "restrict model capabilities through function-calling allow-lists."
        ),
        cwe_id=74,
        owasp_category="LLM01",
    ),

    # ---- Model Poisoning Risk ----
    VulnerabilityPattern(
        name="Model Poisoning — Unvalidated Training Data Pipeline",
        pattern=re.compile(
            r"""(?:(?:\.fit|\.train|train_model|fine_tune|finetune)"""
            r"""\s*\(.*(?:user_data|raw_data|unfiltered|external_data|scraped)"""
            r"""|(?:training_data|dataset)\s*=\s*(?:pd\.read_csv|load_dataset|json\.load"""
            r"""|open\(|requests\.get))""",
            re.IGNORECASE,
        ),
        severity="high",
        description=(
            "Training or fine-tuning pipeline ingests data without validation or "
            "integrity checks. Poisoned training data can embed backdoors or bias "
            "the model to produce dangerous outputs."
        ),
        recommendation=(
            "Implement data provenance tracking and integrity validation for all "
            "training data. Use anomaly detection on training datasets. Pin dataset "
            "versions and verify checksums before training runs."
        ),
        cwe_id=20,
        owasp_category="LLM03",
    ),

    # ---- Insecure Model Loading ----
    VulnerabilityPattern(
        name="Insecure Model Loading — Pickle/Joblib Deserialization",
        pattern=re.compile(
            r"""(?:pickle\.load|pickle\.loads|joblib\.load|torch\.load"""
            r"""|dill\.load|shelve\.open|cloudpickle\.load"""
            r"""|np\.load\(.*allow_pickle\s*=\s*True)""",
            re.IGNORECASE,
        ),
        severity="critical",
        description=(
            "Model or data is deserialized using pickle, joblib, or torch.load "
            "without verification. These formats can execute arbitrary code during "
            "loading, enabling remote code execution if the file is attacker-controlled."
        ),
        recommendation=(
            "Use safe serialization formats (safetensors, ONNX, JSON). If pickle "
            "is unavoidable, verify file checksums and provenance. Use torch.load "
            "with weights_only=True. Isolate model loading in sandboxed environments."
        ),
        cwe_id=502,
        owasp_category="LLM05",
        confidence="high",
    ),

    # ---- API Key Exposure in AI Config ----
    VulnerabilityPattern(
        name="API Key Exposure — Hardcoded AI Service Credentials",
        pattern=re.compile(
            r"""(?:(?:openai|anthropic|huggingface|hf|cohere|replicate|palm|gemini)"""
            r"""[_.]?(?:api[_.]?key|secret|token)\s*=\s*["'][a-zA-Z0-9_\-]{20,}["']"""
            r"""|(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|HUGGINGFACE_TOKEN"""
            r"""|COHERE_API_KEY|REPLICATE_API_TOKEN)"""
            r"""\s*=\s*["'][a-zA-Z0-9_\-]{20,}["']"""
            r"""|sk-[a-zA-Z0-9]{20,}"""
            r"""|sk-ant-[a-zA-Z0-9]{20,}"""
            r"""|hf_[a-zA-Z0-9]{20,})""",
            re.IGNORECASE,
        ),
        severity="critical",
        description=(
            "AI service API keys (OpenAI, Anthropic, HuggingFace, etc.) are "
            "hardcoded in source code. Exposed keys enable unauthorized usage, "
            "cost abuse, and potential data exfiltration through the AI provider."
        ),
        recommendation=(
            "Store API keys in environment variables or a secrets manager "
            "(e.g., AWS Secrets Manager, HashiCorp Vault). Add patterns to "
            ".gitignore and use pre-commit hooks like detect-secrets."
        ),
        cwe_id=798,
        owasp_category="LLM06",
        confidence="high",
    ),

    # ---- Excessive AI Permissions ----
    VulnerabilityPattern(
        name="Excessive AI Permissions — Unrestricted Agent Tool Access",
        pattern=re.compile(
            r"""(?:(?:tools|functions|plugins)\s*=\s*\[?\s*["'](?:all|shell|exec"""
            r"""|execute|run_command|file_write|database_query|sudo)"""
            r"""|allow_(?:all|dangerous|code_execution)\s*=\s*True"""
            r"""|(?:agent|assistant)\.(?:run|execute)\s*\(.*(?:unrestricted|all_tools|no_limit"""
            r"""|shell_access))""",
            re.IGNORECASE,
        ),
        severity="high",
        description=(
            "AI agent or assistant is configured with overly broad tool access "
            "(shell execution, file writes, database queries) without restrictions. "
            "A prompt injection could leverage these tools for system compromise."
        ),
        recommendation=(
            "Apply principle of least privilege: restrict agent tools to the "
            "minimum needed. Implement tool-level authorization, confirmation "
            "prompts for destructive actions, and output sandboxing."
        ),
        cwe_id=250,
        owasp_category="LLM08",
    ),

    # ---- Training Data Leakage ----
    VulnerabilityPattern(
        name="Training Data Leakage — PII in Training Datasets",
        pattern=re.compile(
            r"""(?:(?:train|fine_?tune|dataset).*(?:email|ssn|social_security"""
            r"""|credit_card|password|phone_number|address|date_of_birth|passport)"""
            r"""|(?:personally_identifiable|pii|sensitive_data).*(?:train|fine_?tune|dataset"""
            r"""|\.fit|model\.train))""",
            re.IGNORECASE,
        ),
        severity="high",
        description=(
            "Training data pipeline may contain personally identifiable information "
            "(PII). Models can memorize and regurgitate sensitive data from their "
            "training set through targeted prompt extraction attacks."
        ),
        recommendation=(
            "Implement PII detection and redaction (e.g., Microsoft Presidio) in "
            "data preprocessing pipelines. Apply differential privacy techniques. "
            "Regularly audit training datasets for sensitive content."
        ),
        cwe_id=359,
        owasp_category="LLM06",
    ),

    # ---- Insecure Model Serving ----
    VulnerabilityPattern(
        name="Insecure Model Serving — Unauthenticated Model Endpoint",
        pattern=re.compile(
            r"""(?:(?:@app\.(?:route|post|get)|@router\.(?:post|get))"""
            r""".*(?:predict|inference|generate|complete|chat|embed)"""
            r"""(?:(?!.*(?:Depends|authenticate|verify_token|auth_required|login_required|api_key|Bearer)).){0,200}"""
            r"""(?:def |async def ))""",
            re.DOTALL | re.IGNORECASE,
        ),
        severity="high",
        description=(
            "Model inference endpoint appears to lack authentication or "
            "authorization. Unauthenticated endpoints allow abuse, cost "
            "exploitation, and potential model extraction attacks."
        ),
        recommendation=(
            "Require authentication (API keys, JWT, OAuth) on all model-serving "
            "endpoints. Implement rate limiting, usage quotas, and request logging. "
            "Consider adding model watermarking to detect extraction."
        ),
        cwe_id=306,
        owasp_category="LLM10",
    ),

    # ---- Output Manipulation ----
    VulnerabilityPattern(
        name="Output Manipulation — LLM Output Used in Security Decisions",
        pattern=re.compile(
            r"""(?:(?:response|output|result|completion|generated|llm_output|ai_response)"""
            r""".*(?:eval\(|exec\(|subprocess|os\.system|shell|sql|query\(|execute\("""
            r"""|\.run\(|isAdmin|is_admin|role\s*=|permission|authorize|access_level"""
            r"""|redirect|url_for|Location:)"""
            r"""|(?:eval|exec|subprocess|os\.system)\s*\(.*(?:response|output|completion"""
            r"""|generated|llm_output|ai_response))""",
            re.IGNORECASE,
        ),
        severity="critical",
        description=(
            "LLM output is used directly in security-critical operations such as "
            "code execution, SQL queries, authorization decisions, or redirects "
            "without validation. An attacker can manipulate LLM output to achieve "
            "code execution or privilege escalation."
        ),
        recommendation=(
            "Never use LLM output directly in security-critical paths. Validate "
            "and sanitize all model outputs. Use structured output parsing with "
            "strict schemas. Implement output allow-listing for critical decisions."
        ),
        cwe_id=94,
        owasp_category="LLM02",
        confidence="high",
    ),

    # ---- Token Limit Exploitation ----
    VulnerabilityPattern(
        name="Token Limit Exploitation — No Input Length Validation",
        pattern=re.compile(
            r"""(?:(?:openai|client|anthropic|llm|model)\.(?:chat\.completions\.create"""
            r"""|complete|generate|messages\.create)"""
            r"""\s*\((?:(?!.*(?:max_tokens|truncat|len\(|length|limit|[:]\s*\d)).){0,300}\))""",
            re.DOTALL | re.IGNORECASE,
        ),
        severity="medium",
        description=(
            "AI API calls lack input length validation or token limits. "
            "Attackers can submit extremely long inputs to cause denial of service "
            "through excessive token consumption and cost inflation."
        ),
        recommendation=(
            "Validate input length before sending to AI APIs. Set max_tokens "
            "limits on all API calls. Implement request-level cost budgets and "
            "rate limiting. Monitor token usage for anomalies."
        ),
        cwe_id=400,
        owasp_category="LLM04",
    ),

    # ---- AI Supply Chain — Untrusted Model Downloads ----
    VulnerabilityPattern(
        name="AI Supply Chain — Untrusted Model Download",
        pattern=re.compile(
            r"""(?:(?:from_pretrained|pipeline|AutoModel|AutoTokenizer"""
            r"""|load_model|download_model|hf_hub_download)"""
            r"""\s*\(\s*["'][^"']*["'](?:(?!.*(?:trust_remote_code\s*=\s*False"""
            r"""|verify|revision|hash|checksum)).){0,100}\)"""
            r"""|trust_remote_code\s*=\s*True)""",
            re.DOTALL | re.IGNORECASE,
        ),
        severity="high",
        description=(
            "Models are downloaded from external registries without integrity "
            "verification, pinned versions, or with trust_remote_code=True. "
            "Malicious models can execute arbitrary code during loading."
        ),
        recommendation=(
            "Pin model versions using specific revisions or commit hashes. Never "
            "set trust_remote_code=True in production. Verify model checksums. "
            "Use organization-approved model registries and audit model sources."
        ),
        cwe_id=829,
        owasp_category="LLM05",
        confidence="high",
    ),
]


# OWASP LLM Top 10 definitions
OWASP_LLM_TOP_10: dict[str, dict[str, str]] = {
    "LLM01": {
        "title": "Prompt Injection",
        "description": "Manipulating LLMs via crafted inputs to cause unintended actions.",
    },
    "LLM02": {
        "title": "Insecure Output Handling",
        "description": "Insufficient validation of LLM outputs leading to downstream security issues.",
    },
    "LLM03": {
        "title": "Training Data Poisoning",
        "description": "Manipulation of training data to introduce vulnerabilities or biases.",
    },
    "LLM04": {
        "title": "Model Denial of Service",
        "description": "Resource-heavy operations causing service degradation via AI models.",
    },
    "LLM05": {
        "title": "Supply Chain Vulnerabilities",
        "description": "Compromised components in the AI/ML supply chain.",
    },
    "LLM06": {
        "title": "Sensitive Information Disclosure",
        "description": "Exposure of confidential data through LLM responses or training data.",
    },
    "LLM07": {
        "title": "Insecure Plugin Design",
        "description": "LLM plugins with insecure inputs or insufficient access control.",
    },
    "LLM08": {
        "title": "Excessive Agency",
        "description": "Granting too much autonomy to LLM-based systems.",
    },
    "LLM09": {
        "title": "Overreliance",
        "description": "Uncritical dependence on LLM outputs without oversight.",
    },
    "LLM10": {
        "title": "Model Theft",
        "description": "Unauthorized access or extraction of proprietary LLM models.",
    },
}

# Keywords that suggest a finding relates to AI/ML
AI_RELATED_KEYWORDS: list[str] = [
    "llm", "gpt", "openai", "anthropic", "claude", "langchain", "huggingface",
    "transformer", "embedding", "vector", "prompt", "inference", "model",
    "tensorflow", "pytorch", "torch", "keras", "scikit", "ml pipeline",
    "ai agent", "chatbot", "rag", "retrieval augmented", "fine-tune",
    "finetune", "training data", "neural", "deep learning", "machine learning",
    "diffusion", "stable diffusion", "midjourney", "copilot", "completion",
    "tokenizer", "attention", "bert", "llama", "mistral", "gemini",
    "palm", "cohere", "replicate", "pickle", "joblib", "safetensors",
]


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class LLMScannerService:
    """AI/ML vulnerability scanner using pattern matching and heuristics."""

    # ------------------------------------------------------------------
    # Code snippet scanning
    # ------------------------------------------------------------------

    def scan_code_snippet(
        self,
        code: str,
        language: str = "python",
        context: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Scan a code snippet for AI/ML-specific vulnerabilities.

        Returns a list of vulnerability matches with type, severity,
        confidence, description, line number, recommendation, CWE, and
        OWASP LLM Top 10 category.
        """
        results: list[VulnerabilityMatch] = []
        lines = code.split("\n")

        for vp in VULNERABILITY_PATTERNS:
            # Skip patterns that don't apply to the given language
            if language.lower() not in vp.languages and "all" not in vp.languages:
                continue

            for line_idx, line in enumerate(lines, start=1):
                # Skip comment-only lines
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                if vp.pattern.search(line):
                    results.append(VulnerabilityMatch(
                        vulnerability_type=vp.name,
                        severity=vp.severity,
                        confidence=vp.confidence,
                        description=vp.description,
                        line_number=line_idx,
                        recommendation=vp.recommendation,
                        cwe_id=vp.cwe_id,
                        owasp_category=vp.owasp_category,
                    ))

            # Also try multi-line matching against the full code block
            for match in vp.pattern.finditer(code):
                match_line = code[: match.start()].count("\n") + 1
                # Avoid duplicating single-line hits
                if not any(
                    r.vulnerability_type == vp.name and r.line_number == match_line
                    for r in results
                ):
                    results.append(VulnerabilityMatch(
                        vulnerability_type=vp.name,
                        severity=vp.severity,
                        confidence=vp.confidence,
                        description=vp.description,
                        line_number=match_line,
                        recommendation=vp.recommendation,
                        cwe_id=vp.cwe_id,
                        owasp_category=vp.owasp_category,
                    ))

        # Contextual confidence boost — if context indicates AI-heavy repo,
        # raise low-confidence matches to medium.
        if context:
            ctx_lower = context.lower()
            ai_context = any(kw in ctx_lower for kw in AI_RELATED_KEYWORDS[:20])
            if ai_context:
                for r in results:
                    if r.confidence == "low":
                        r.confidence = "medium"

        # Deduplicate by (type, line)
        seen: set[tuple[str, int]] = set()
        deduped: list[VulnerabilityMatch] = []
        for r in results:
            key = (r.vulnerability_type, r.line_number)
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        # Sort by severity priority
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        deduped.sort(key=lambda v: (severity_order.get(v.severity, 5), v.line_number))

        return [v.to_dict() for v in deduped]

    # ------------------------------------------------------------------
    # Product-level finding analysis
    # ------------------------------------------------------------------

    async def scan_product_findings(
        self, db: AsyncSession, product_id: int
    ) -> list[dict[str, Any]]:
        """Re-analyze existing findings to identify AI/ML-related security issues.

        Scans finding titles, descriptions, file paths, and tool types for
        AI-related keywords that may have been miscategorized by traditional
        scanners.
        """
        query = (
            select(Finding)
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
                Finding.status.in_([FindingStatus.ACTIVE, FindingStatus.VERIFIED]),
            )
            .order_by(Finding.severity, Finding.created_at.desc())
        )
        result = await db.execute(query)
        findings = list(result.scalars().all())

        ai_findings: list[dict[str, Any]] = []

        for finding in findings:
            searchable = " ".join(filter(None, [
                finding.title,
                finding.description or "",
                finding.file_path or "",
                finding.component or "",
            ])).lower()

            matched_keywords: list[str] = []
            for kw in AI_RELATED_KEYWORDS:
                if kw in searchable:
                    matched_keywords.append(kw)

            if not matched_keywords:
                continue

            # Determine AI risk category
            ai_category = self._classify_ai_finding(searchable, matched_keywords)

            ai_findings.append({
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
                "original_cwe": finding.cwe,
                "file_path": finding.file_path,
                "ai_keywords_matched": matched_keywords,
                "ai_risk_category": ai_category,
                "owasp_llm_mapping": self._map_category_to_owasp(ai_category),
                "recommendation": self._get_category_recommendation(ai_category),
            })

        return ai_findings

    # ------------------------------------------------------------------
    # AI risk assessment
    # ------------------------------------------------------------------

    async def get_ai_risk_assessment(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, Any]:
        """Produce an overall AI security risk assessment for a product."""
        ai_findings = await self.scan_product_findings(db, product_id)

        # Count total open findings to determine AI exposure
        total_q = (
            select(func.count(Finding.id))
            .where(
                Finding.product_id == product_id,
                Finding.is_duplicate == False,  # noqa: E712
                Finding.status.in_([FindingStatus.ACTIVE, FindingStatus.VERIFIED]),
            )
        )
        total_open = (await db.execute(total_q)).scalar() or 0

        severity_breakdown: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts: dict[str, int] = {}
        for af in ai_findings:
            sev = af["severity"]
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            cat = af["ai_risk_category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1

        ai_count = len(ai_findings)
        ai_ratio = ai_count / total_open if total_open > 0 else 0.0

        # Exposure level
        if severity_breakdown["critical"] > 0 or ai_ratio > 0.3:
            exposure = "critical"
        elif severity_breakdown["high"] > 2 or ai_ratio > 0.2:
            exposure = "high"
        elif ai_count > 5 or ai_ratio > 0.1:
            exposure = "medium"
        elif ai_count > 0:
            exposure = "low"
        else:
            exposure = "none"

        # Individual risk dimensions
        prompt_risk = self._assess_dimension_risk(
            category_counts, ["prompt_injection", "indirect_prompt_injection"]
        )
        poisoning_risk = self._assess_dimension_risk(
            category_counts, ["data_poisoning", "training_data_leakage"]
        )
        supply_chain_risk = self._assess_dimension_risk(
            category_counts, ["insecure_model_loading", "model_supply_chain", "api_key_exposure"]
        )

        recommendations = self._build_risk_recommendations(
            exposure, category_counts, severity_breakdown
        )

        assessment = AIRiskAssessment(
            product_id=product_id,
            ai_exposure_level=exposure,
            prompt_injection_risk=prompt_risk,
            data_poisoning_risk=poisoning_risk,
            model_supply_chain_risk=supply_chain_risk,
            total_ai_findings=ai_count,
            severity_breakdown=severity_breakdown,
            recommendations=recommendations,
        )
        return assessment.to_dict()

    # ------------------------------------------------------------------
    # OWASP LLM Top 10 mapping
    # ------------------------------------------------------------------

    async def get_owasp_llm_top10_mapping(
        self, db: AsyncSession, product_id: int
    ) -> dict[str, Any]:
        """Map findings to the OWASP LLM Top 10 categories."""
        ai_findings = await self.scan_product_findings(db, product_id)

        mapping: dict[str, dict[str, Any]] = {}
        for code, info in OWASP_LLM_TOP_10.items():
            mapping[code] = {
                "code": code,
                "title": info["title"],
                "description": info["description"],
                "finding_count": 0,
                "findings": [],
                "risk_level": "none",
            }

        for af in ai_findings:
            owasp_code = af.get("owasp_llm_mapping", "")
            if owasp_code in mapping:
                mapping[owasp_code]["finding_count"] += 1
                mapping[owasp_code]["findings"].append({
                    "finding_id": af["finding_id"],
                    "title": af["title"],
                    "severity": af["severity"],
                })

        # Assign risk levels
        for entry in mapping.values():
            count = entry["finding_count"]
            severities = [f["severity"] for f in entry["findings"]]
            if "critical" in severities:
                entry["risk_level"] = "critical"
            elif count > 3 or "high" in severities:
                entry["risk_level"] = "high"
            elif count > 0:
                entry["risk_level"] = "medium"
            else:
                entry["risk_level"] = "none"

        categories = sorted(mapping.values(), key=lambda c: c["code"])
        total_mapped = sum(c["finding_count"] for c in categories)
        coverage = sum(1 for c in categories if c["finding_count"] > 0)

        return {
            "product_id": product_id,
            "total_mapped_findings": total_mapped,
            "categories_affected": coverage,
            "categories": categories,
        }

    # ------------------------------------------------------------------
    # Org-wide overview
    # ------------------------------------------------------------------

    async def get_org_overview(
        self, db: AsyncSession
    ) -> dict[str, Any]:
        """Get organisation-wide AI security overview across all products."""
        products_result = await db.execute(select(Product).order_by(Product.name))
        products = list(products_result.scalars().all())

        product_summaries: list[dict[str, Any]] = []
        total_ai_findings = 0
        org_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        exposure_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}

        for product in products:
            assessment = await self.get_ai_risk_assessment(db, product.id)
            total_ai_findings += assessment["total_ai_findings"]
            exposure_counts[assessment["ai_exposure_level"]] = (
                exposure_counts.get(assessment["ai_exposure_level"], 0) + 1
            )
            for sev, count in assessment["severity_breakdown"].items():
                org_severity[sev] = org_severity.get(sev, 0) + count

            product_summaries.append({
                "product_id": product.id,
                "product_name": product.name,
                "ai_exposure_level": assessment["ai_exposure_level"],
                "total_ai_findings": assessment["total_ai_findings"],
                "prompt_injection_risk": assessment["prompt_injection_risk"],
                "model_supply_chain_risk": assessment["model_supply_chain_risk"],
            })

        # Org-level risk
        if exposure_counts["critical"] > 0:
            org_risk = "critical"
        elif exposure_counts["high"] > 1:
            org_risk = "high"
        elif total_ai_findings > 10:
            org_risk = "medium"
        elif total_ai_findings > 0:
            org_risk = "low"
        else:
            org_risk = "none"

        return {
            "org_ai_risk_level": org_risk,
            "total_products": len(products),
            "total_ai_findings": total_ai_findings,
            "severity_breakdown": org_severity,
            "exposure_distribution": exposure_counts,
            "product_summaries": sorted(
                product_summaries,
                key=lambda p: {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}.get(
                    p["ai_exposure_level"], 5
                ),
            ),
            "top_recommendations": self._build_org_recommendations(
                org_risk, org_severity, exposure_counts
            ),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_ai_finding(text: str, keywords: list[str]) -> str:
        """Classify a finding into an AI risk category based on matched keywords."""
        keyword_set = set(keywords)
        text_lower = text.lower()

        if "prompt" in keyword_set or "injection" in text_lower:
            return "prompt_injection"
        if any(k in keyword_set for k in ["pickle", "joblib", "safetensors"]):
            return "insecure_model_loading"
        if any(k in keyword_set for k in ["training data", "fine-tune", "finetune"]):
            if any(w in text_lower for w in ["pii", "leak", "sensitive", "personal"]):
                return "training_data_leakage"
            return "data_poisoning"
        if any(k in keyword_set for k in ["openai", "anthropic", "cohere", "replicate"]):
            if any(w in text_lower for w in ["key", "secret", "token", "credential"]):
                return "api_key_exposure"
            return "model_supply_chain"
        if any(k in keyword_set for k in ["langchain", "ai agent"]):
            if any(w in text_lower for w in ["tool", "permission", "access", "execute"]):
                return "excessive_permissions"
            return "prompt_injection"
        if any(k in keyword_set for k in ["inference", "embedding", "vector"]):
            if any(w in text_lower for w in ["auth", "unauth", "public", "endpoint"]):
                return "insecure_serving"
            return "model_supply_chain"
        if any(k in keyword_set for k in ["huggingface", "transformer", "bert", "llama", "mistral"]):
            return "model_supply_chain"

        return "general_ai_risk"

    @staticmethod
    def _map_category_to_owasp(category: str) -> str:
        """Map an internal AI risk category to an OWASP LLM Top 10 code."""
        mapping = {
            "prompt_injection": "LLM01",
            "indirect_prompt_injection": "LLM01",
            "insecure_output": "LLM02",
            "data_poisoning": "LLM03",
            "token_exploitation": "LLM04",
            "insecure_model_loading": "LLM05",
            "model_supply_chain": "LLM05",
            "api_key_exposure": "LLM06",
            "training_data_leakage": "LLM06",
            "excessive_permissions": "LLM08",
            "insecure_serving": "LLM10",
            "general_ai_risk": "LLM09",
        }
        return mapping.get(category, "LLM09")

    @staticmethod
    def _get_category_recommendation(category: str) -> str:
        """Return a brief recommendation for an AI risk category."""
        recs = {
            "prompt_injection": (
                "Implement input sanitization, use structured prompts with role "
                "separation, and apply output validation."
            ),
            "insecure_model_loading": (
                "Switch to safe serialization formats (safetensors, ONNX). "
                "Verify model checksums before loading."
            ),
            "data_poisoning": (
                "Validate and audit all training data. Implement data provenance "
                "tracking and anomaly detection."
            ),
            "training_data_leakage": (
                "Run PII detection on training datasets. Apply differential "
                "privacy and data anonymization."
            ),
            "api_key_exposure": (
                "Move AI service keys to environment variables or a secrets "
                "manager. Add pre-commit secret scanning."
            ),
            "excessive_permissions": (
                "Restrict agent tool access to minimum required capabilities. "
                "Add confirmation gates for destructive actions."
            ),
            "insecure_serving": (
                "Add authentication and rate limiting to all model endpoints. "
                "Implement usage monitoring and quotas."
            ),
            "model_supply_chain": (
                "Pin model versions, verify checksums, and use approved model "
                "registries. Audit model dependencies."
            ),
            "general_ai_risk": (
                "Review AI/ML components for security best practices. Consult "
                "the OWASP LLM Top 10 for guidance."
            ),
        }
        return recs.get(category, recs["general_ai_risk"])

    @staticmethod
    def _assess_dimension_risk(
        category_counts: dict[str, int], categories: list[str]
    ) -> str:
        """Assess risk level for a specific dimension based on finding counts."""
        total = sum(category_counts.get(c, 0) for c in categories)
        if total >= 5:
            return "critical"
        if total >= 3:
            return "high"
        if total >= 1:
            return "medium"
        return "low"

    @staticmethod
    def _build_risk_recommendations(
        exposure: str,
        category_counts: dict[str, int],
        severity_breakdown: dict[str, int],
    ) -> list[str]:
        """Build product-level AI risk recommendations."""
        recs: list[str] = []

        if severity_breakdown.get("critical", 0) > 0:
            recs.append(
                "Immediately address critical AI-related findings — these may "
                "enable prompt injection or remote code execution."
            )

        if category_counts.get("prompt_injection", 0) > 0:
            recs.append(
                "Implement prompt injection defenses: input sanitization, "
                "role-based prompt separation, and output validation."
            )

        if category_counts.get("insecure_model_loading", 0) > 0:
            recs.append(
                "Replace pickle/joblib deserialization with safe formats "
                "(safetensors, ONNX) to prevent code execution attacks."
            )

        if category_counts.get("api_key_exposure", 0) > 0:
            recs.append(
                "Rotate exposed AI service API keys immediately and migrate "
                "to a secrets manager."
            )

        if category_counts.get("model_supply_chain", 0) > 0:
            recs.append(
                "Audit AI model sources and pin versions. Disable "
                "trust_remote_code in HuggingFace model loading."
            )

        if category_counts.get("excessive_permissions", 0) > 0:
            recs.append(
                "Review and restrict AI agent tool permissions. Apply least-"
                "privilege principles to all AI-driven automation."
            )

        if not recs:
            if exposure == "none":
                recs.append(
                    "No AI-specific vulnerabilities detected. Continue monitoring "
                    "as AI/ML components are added."
                )
            else:
                recs.append(
                    "Review AI/ML components against the OWASP LLM Top 10 "
                    "and address findings by severity."
                )

        return recs

    @staticmethod
    def _build_org_recommendations(
        org_risk: str,
        severity: dict[str, int],
        exposure_counts: dict[str, int],
    ) -> list[str]:
        """Build org-wide AI security recommendations."""
        recs: list[str] = []

        if severity.get("critical", 0) > 0:
            recs.append(
                f"Address {severity['critical']} critical AI-related finding(s) "
                f"across the organization as a top priority."
            )

        if exposure_counts.get("critical", 0) > 0:
            recs.append(
                f"{exposure_counts['critical']} product(s) have critical AI "
                f"exposure — initiate immediate security reviews."
            )

        if (exposure_counts.get("critical", 0) + exposure_counts.get("high", 0)) > 2:
            recs.append(
                "Establish an AI security policy covering prompt injection "
                "defenses, model supply chain verification, and data privacy."
            )

        if org_risk in ("critical", "high"):
            recs.append(
                "Consider deploying an AI firewall or gateway to monitor and "
                "filter LLM inputs/outputs across products."
            )

        if not recs:
            recs.append(
                "AI security posture is healthy. Maintain regular scanning as "
                "AI/ML adoption grows."
            )

        return recs
