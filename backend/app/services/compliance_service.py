"""Compliance Mapping Engine for Foxnode ASPM.

Maps security findings (by CWE and tool type) to industry compliance
frameworks and calculates posture, coverage, and gap analysis.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ComplianceControl:
    """A single control/requirement within a compliance framework."""

    control_id: str
    title: str
    description: str


@dataclass
class ComplianceFramework:
    """Definition of a compliance framework and its controls."""

    framework_id: str
    name: str
    version: str
    description: str
    controls: list[ComplianceControl] = field(default_factory=list)


@dataclass
class ControlFinding:
    """Represents the mapping of a finding to a compliance control."""

    control_id: str
    finding_id: int
    finding_title: str
    severity: str
    status: str
    cwe: Optional[int] = None


@dataclass
class ControlGap:
    """A control that has no coverage or is failing."""

    control_id: str
    title: str
    gap_type: str  # "no_coverage" or "failing"
    details: str


@dataclass
class ComplianceReport:
    """Result of evaluating a framework against current findings."""

    framework_id: str
    framework_name: str
    version: str
    total_controls: int
    controls_with_findings: int
    passing_controls: int
    failing_controls: int
    compliance_percentage: float
    gaps: list[ControlGap]
    mapped_findings_count: int


# ---------------------------------------------------------------------------
# Framework definitions
# ---------------------------------------------------------------------------

OWASP_TOP_10_2021 = ComplianceFramework(
    framework_id="owasp-top10-2021",
    name="OWASP Top 10",
    version="2021",
    description="OWASP Top 10 Web Application Security Risks (2021 edition)",
    controls=[
        ComplianceControl("A01:2021", "Broken Access Control", "Failures related to access control enforcement, allowing users to act outside their intended permissions."),
        ComplianceControl("A02:2021", "Cryptographic Failures", "Failures related to cryptography that lead to exposure of sensitive data."),
        ComplianceControl("A03:2021", "Injection", "Injection flaws such as SQL, NoSQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter."),
        ComplianceControl("A04:2021", "Insecure Design", "Risks related to design and architectural flaws, missing or ineffective control design."),
        ComplianceControl("A05:2021", "Security Misconfiguration", "Missing appropriate security hardening or improperly configured permissions."),
        ComplianceControl("A06:2021", "Vulnerable and Outdated Components", "Using components with known vulnerabilities or outdated software."),
        ComplianceControl("A07:2021", "Identification and Authentication Failures", "Failures related to authentication and session management."),
        ComplianceControl("A08:2021", "Software and Data Integrity Failures", "Failures related to code and infrastructure that do not protect against integrity violations."),
        ComplianceControl("A09:2021", "Security Logging and Monitoring Failures", "Insufficient logging, detection, monitoring, and active response."),
        ComplianceControl("A10:2021", "Server-Side Request Forgery", "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL."),
    ],
)

CIS_BENCHMARKS = ComplianceFramework(
    framework_id="cis-benchmarks",
    name="CIS Benchmarks",
    version="1.0",
    description="Center for Internet Security benchmarks for secure configuration of infrastructure and cloud environments.",
    controls=[
        ComplianceControl("CIS-1.1", "Inventory of Authorized and Unauthorized Devices", "Maintain an accurate inventory of all technology assets."),
        ComplianceControl("CIS-1.2", "Inventory of Authorized and Unauthorized Software", "Maintain an inventory of authorized software and monitor for unauthorized installs."),
        ComplianceControl("CIS-2.1", "Secure Configuration for Hardware and Software", "Establish and maintain secure configurations for enterprise assets."),
        ComplianceControl("CIS-3.1", "Data Protection", "Establish and maintain data management and protection processes."),
        ComplianceControl("CIS-4.1", "Secure Configuration of Enterprise Assets and Software", "Establish secure configuration processes for network infrastructure."),
        ComplianceControl("CIS-5.1", "Account Management", "Use processes and tools to assign and manage credentials for user accounts."),
        ComplianceControl("CIS-6.1", "Access Control Management", "Use processes and tools to manage access control for enterprise assets."),
        ComplianceControl("CIS-7.1", "Continuous Vulnerability Management", "Develop a plan to continuously assess and track vulnerabilities."),
        ComplianceControl("CIS-8.1", "Audit Log Management", "Collect, alert, review, and retain audit logs of events."),
        ComplianceControl("CIS-9.1", "Email and Web Browser Protections", "Improve protections and detections of threats from email and web vectors."),
    ],
)

PCI_DSS_V4 = ComplianceFramework(
    framework_id="pci-dss-v4",
    name="PCI-DSS",
    version="4.0",
    description="Payment Card Industry Data Security Standard version 4.0.",
    controls=[
        ComplianceControl("PCI-1.1", "Install and Maintain Network Security Controls", "Network security controls are installed and maintained."),
        ComplianceControl("PCI-2.1", "Apply Secure Configurations to All System Components", "Secure configurations are applied to all system components."),
        ComplianceControl("PCI-3.1", "Protect Stored Account Data", "Stored account data is protected."),
        ComplianceControl("PCI-4.1", "Protect Cardholder Data with Strong Cryptography During Transmission", "Cardholder data is protected with strong cryptography during transmission over open, public networks."),
        ComplianceControl("PCI-5.1", "Protect All Systems and Networks from Malicious Software", "Malicious software is prevented or detected and addressed."),
        ComplianceControl("PCI-6.1", "Develop and Maintain Secure Systems and Software", "Security vulnerabilities are identified and addressed."),
        ComplianceControl("PCI-6.2", "Bespoke and Custom Software Is Developed Securely", "Bespoke and custom software is developed securely."),
        ComplianceControl("PCI-6.2.4", "Software Engineering Techniques Prevent Injection Attacks", "Software engineering techniques or other methods prevent common software attacks."),
        ComplianceControl("PCI-6.3", "Security Vulnerabilities Are Identified and Addressed", "Vulnerabilities are identified and addressed via patching and secure development."),
        ComplianceControl("PCI-7.1", "Access to System Components and Data Is Restricted", "Access is restricted by business need to know."),
        ComplianceControl("PCI-8.1", "User Identification and Authentication", "User identification and authentication to system components."),
        ComplianceControl("PCI-10.1", "Log and Monitor All Access to System Components and Cardholder Data", "Log and monitor all access to system components and cardholder data."),
        ComplianceControl("PCI-11.1", "Test Security of Systems and Networks Regularly", "Security of systems and networks is tested regularly."),
        ComplianceControl("PCI-12.1", "Support Information Security with Organizational Policies and Programs", "Information security policy is established and maintained."),
    ],
)

SOC2 = ComplianceFramework(
    framework_id="soc2",
    name="SOC 2",
    version="2017",
    description="Service Organization Control 2 — Trust Services Criteria.",
    controls=[
        ComplianceControl("SOC2-CC6.1", "Logical and Physical Access Controls", "The entity implements logical access security software, infrastructure, and architectures."),
        ComplianceControl("SOC2-CC6.2", "Prior to Issuing System Credentials", "Credentials are managed and validated prior to issuance."),
        ComplianceControl("SOC2-CC6.3", "Role-Based Access and Least Privilege", "The entity authorizes, modifies, or removes access based on roles."),
        ComplianceControl("SOC2-CC6.6", "Restrict Access — Boundaries of System", "The entity restricts the ability of unauthorized persons to access system boundaries."),
        ComplianceControl("SOC2-CC7.1", "Detection and Monitoring Mechanisms", "To meet its objectives, the entity uses detection and monitoring procedures."),
        ComplianceControl("SOC2-CC7.2", "Monitor System Components for Anomalies", "The entity monitors system components for anomalies that are indicative of malicious acts."),
        ComplianceControl("SOC2-CC8.1", "Change Management Process", "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes."),
        ComplianceControl("SOC2-A1.1", "Availability — Capacity Management", "The entity maintains, monitors, and evaluates current processing capacity."),
        ComplianceControl("SOC2-PI1.1", "Processing Integrity — Completeness and Accuracy", "The entity uses processing integrity objectives to meet its objectives."),
        ComplianceControl("SOC2-C1.1", "Confidentiality — Protection of Confidential Information", "The entity identifies and maintains confidential information to meet its objectives."),
    ],
)

ISO_27001 = ComplianceFramework(
    framework_id="iso-27001",
    name="ISO 27001",
    version="2022",
    description="ISO/IEC 27001 Information Security Management System (Annex A controls).",
    controls=[
        ComplianceControl("ISO-A.5", "Information Security Policies", "Management direction for information security."),
        ComplianceControl("ISO-A.6", "Organization of Information Security", "Internal organization and mobile device/teleworking security."),
        ComplianceControl("ISO-A.7", "Human Resource Security", "Prior to, during, and termination of employment security."),
        ComplianceControl("ISO-A.8", "Asset Management", "Responsibility for assets, information classification, and media handling."),
        ComplianceControl("ISO-A.9", "Access Control", "Business requirements of access control, user access management, and system access control."),
        ComplianceControl("ISO-A.10", "Cryptography", "Cryptographic controls to protect information confidentiality and integrity."),
        ComplianceControl("ISO-A.12", "Operations Security", "Operational procedures, protection from malware, backup, logging, and monitoring."),
        ComplianceControl("ISO-A.13", "Communications Security", "Network security management and information transfer."),
        ComplianceControl("ISO-A.14", "System Acquisition, Development and Maintenance", "Security requirements of information systems, secure development, and test data."),
        ComplianceControl("ISO-A.16", "Information Security Incident Management", "Management of information security incidents and improvements."),
        ComplianceControl("ISO-A.18", "Compliance", "Compliance with legal and contractual requirements, and information security reviews."),
    ],
)

# Ordered registry of all frameworks
FRAMEWORKS: dict[str, ComplianceFramework] = {
    fw.framework_id: fw
    for fw in [OWASP_TOP_10_2021, CIS_BENCHMARKS, PCI_DSS_V4, SOC2, ISO_27001]
}


# ---------------------------------------------------------------------------
# CWE → control mapping
# ---------------------------------------------------------------------------

# Maps CWE numbers to a list of (framework_id, control_id) tuples.
CWE_TO_CONTROLS: dict[int, list[tuple[str, str]]] = {
    # A01:2021 Broken Access Control
    284: [("owasp-top10-2021", "A01:2021"), ("pci-dss-v4", "PCI-7.1"), ("soc2", "SOC2-CC6.1"), ("iso-27001", "ISO-A.9")],
    285: [("owasp-top10-2021", "A01:2021"), ("pci-dss-v4", "PCI-7.1"), ("soc2", "SOC2-CC6.3")],
    639: [("owasp-top10-2021", "A01:2021"), ("pci-dss-v4", "PCI-7.1")],
    862: [("owasp-top10-2021", "A01:2021"), ("soc2", "SOC2-CC6.1")],
    863: [("owasp-top10-2021", "A01:2021"), ("soc2", "SOC2-CC6.3")],
    22:  [("owasp-top10-2021", "A01:2021")],
    425: [("owasp-top10-2021", "A01:2021")],

    # A02:2021 Cryptographic Failures
    200: [("owasp-top10-2021", "A02:2021"), ("pci-dss-v4", "PCI-3.1"), ("iso-27001", "ISO-A.10")],
    327: [("owasp-top10-2021", "A02:2021"), ("pci-dss-v4", "PCI-4.1"), ("iso-27001", "ISO-A.10")],
    328: [("owasp-top10-2021", "A02:2021"), ("pci-dss-v4", "PCI-4.1"), ("iso-27001", "ISO-A.10")],
    310: [("owasp-top10-2021", "A02:2021"), ("pci-dss-v4", "PCI-4.1")],
    312: [("owasp-top10-2021", "A02:2021"), ("pci-dss-v4", "PCI-3.1")],
    319: [("owasp-top10-2021", "A02:2021"), ("pci-dss-v4", "PCI-4.1")],
    326: [("owasp-top10-2021", "A02:2021"), ("pci-dss-v4", "PCI-4.1"), ("iso-27001", "ISO-A.10")],
    311: [("owasp-top10-2021", "A02:2021"), ("pci-dss-v4", "PCI-3.1")],

    # A03:2021 Injection
    89:  [("owasp-top10-2021", "A03:2021"), ("pci-dss-v4", "PCI-6.2.4"), ("iso-27001", "ISO-A.14")],
    564: [("owasp-top10-2021", "A03:2021"), ("pci-dss-v4", "PCI-6.2.4")],
    79:  [("owasp-top10-2021", "A03:2021"), ("pci-dss-v4", "PCI-6.2.4"), ("iso-27001", "ISO-A.14")],
    87:  [("owasp-top10-2021", "A03:2021"), ("pci-dss-v4", "PCI-6.2.4")],
    77:  [("owasp-top10-2021", "A03:2021"), ("pci-dss-v4", "PCI-6.2.4")],
    78:  [("owasp-top10-2021", "A03:2021"), ("pci-dss-v4", "PCI-6.2.4")],
    90:  [("owasp-top10-2021", "A03:2021"), ("pci-dss-v4", "PCI-6.2.4")],
    917: [("owasp-top10-2021", "A03:2021"), ("pci-dss-v4", "PCI-6.2.4")],
    611: [("owasp-top10-2021", "A03:2021")],

    # A04:2021 Insecure Design
    209: [("owasp-top10-2021", "A04:2021"), ("iso-27001", "ISO-A.14")],
    256: [("owasp-top10-2021", "A04:2021")],
    501: [("owasp-top10-2021", "A04:2021")],
    522: [("owasp-top10-2021", "A04:2021")],

    # A05:2021 Security Misconfiguration
    16:  [("owasp-top10-2021", "A05:2021"), ("pci-dss-v4", "PCI-2.1"), ("soc2", "SOC2-CC8.1")],
    2:   [("owasp-top10-2021", "A05:2021"), ("pci-dss-v4", "PCI-2.1")],
    215: [("owasp-top10-2021", "A05:2021")],
    611: [("owasp-top10-2021", "A05:2021")],
    942: [("owasp-top10-2021", "A05:2021")],

    # A06:2021 Vulnerable and Outdated Components
    1104: [("owasp-top10-2021", "A06:2021"), ("pci-dss-v4", "PCI-6.3"), ("iso-27001", "ISO-A.12")],
    937:  [("owasp-top10-2021", "A06:2021"), ("pci-dss-v4", "PCI-6.3")],

    # A07:2021 Identification and Authentication Failures
    287: [("owasp-top10-2021", "A07:2021"), ("pci-dss-v4", "PCI-8.1"), ("soc2", "SOC2-CC6.2"), ("iso-27001", "ISO-A.9")],
    384: [("owasp-top10-2021", "A07:2021"), ("pci-dss-v4", "PCI-8.1")],
    613: [("owasp-top10-2021", "A07:2021"), ("pci-dss-v4", "PCI-8.1")],
    620: [("owasp-top10-2021", "A07:2021")],
    798: [("owasp-top10-2021", "A07:2021"), ("soc2", "SOC2-CC6.2")],
    307: [("owasp-top10-2021", "A07:2021"), ("pci-dss-v4", "PCI-8.1")],

    # A08:2021 Software and Data Integrity Failures
    502: [("owasp-top10-2021", "A08:2021"), ("iso-27001", "ISO-A.14")],
    829: [("owasp-top10-2021", "A08:2021"), ("soc2", "SOC2-CC8.1")],
    494: [("owasp-top10-2021", "A08:2021"), ("soc2", "SOC2-CC8.1")],
    345: [("owasp-top10-2021", "A08:2021")],

    # A09:2021 Security Logging and Monitoring Failures
    778: [("owasp-top10-2021", "A09:2021"), ("pci-dss-v4", "PCI-10.1"), ("soc2", "SOC2-CC7.1"), ("iso-27001", "ISO-A.12")],
    223: [("owasp-top10-2021", "A09:2021"), ("pci-dss-v4", "PCI-10.1")],
    532: [("owasp-top10-2021", "A09:2021")],

    # A10:2021 Server-Side Request Forgery
    918: [("owasp-top10-2021", "A10:2021"), ("pci-dss-v4", "PCI-6.2.4"), ("iso-27001", "ISO-A.13")],
    441: [("owasp-top10-2021", "A10:2021")],
}


# ---------------------------------------------------------------------------
# Tool type → control mapping
# ---------------------------------------------------------------------------

# Maps scanner tool_type values to relevant (framework_id, control_id) pairs.
TOOL_TYPE_TO_CONTROLS: dict[str, list[tuple[str, str]]] = {
    "SAST": [
        ("owasp-top10-2021", "A03:2021"),
        ("pci-dss-v4", "PCI-6.2"),
        ("iso-27001", "ISO-A.14"),
    ],
    "DAST": [
        ("owasp-top10-2021", "A05:2021"),
        ("pci-dss-v4", "PCI-11.1"),
        ("iso-27001", "ISO-A.14"),
    ],
    "SCA": [
        ("owasp-top10-2021", "A06:2021"),
        ("pci-dss-v4", "PCI-6.3"),
        ("iso-27001", "ISO-A.12"),
    ],
    "IaC": [
        ("cis-benchmarks", "CIS-2.1"),
        ("cis-benchmarks", "CIS-4.1"),
        ("pci-dss-v4", "PCI-2.1"),
        ("soc2", "SOC2-CC8.1"),
    ],
    "SECRET": [
        ("owasp-top10-2021", "A07:2021"),
        ("pci-dss-v4", "PCI-3.1"),
        ("soc2", "SOC2-CC6.1"),
        ("iso-27001", "ISO-A.9"),
    ],
    "CONTAINER": [
        ("cis-benchmarks", "CIS-2.1"),
        ("cis-benchmarks", "CIS-7.1"),
        ("pci-dss-v4", "PCI-5.1"),
    ],
    "CLOUD": [
        ("cis-benchmarks", "CIS-4.1"),
        ("cis-benchmarks", "CIS-6.1"),
        ("soc2", "SOC2-CC6.6"),
    ],
}


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class ComplianceService:
    """Evaluates security findings against compliance frameworks."""

    def list_frameworks(self) -> list[dict]:
        """Return metadata for all supported frameworks."""
        return [
            {
                "framework_id": fw.framework_id,
                "name": fw.name,
                "version": fw.version,
                "description": fw.description,
                "total_controls": len(fw.controls),
            }
            for fw in FRAMEWORKS.values()
        ]

    async def generate_report(
        self,
        db: AsyncSession,
        framework_id: str,
        product_id: Optional[int] = None,
    ) -> ComplianceReport:
        """Generate a compliance report for a single framework.

        Args:
            db: Database session.
            framework_id: ID of the framework to evaluate.
            product_id: Optional product filter.

        Returns:
            ComplianceReport with posture calculations.

        Raises:
            ValueError: If the framework_id is not recognised.
        """
        framework = FRAMEWORKS.get(framework_id)
        if framework is None:
            raise ValueError(f"Unknown framework: {framework_id}")

        # Fetch active/verified findings that have a CWE or tool_type
        query = select(Finding).where(
            Finding.status.in_([FindingStatus.ACTIVE, FindingStatus.VERIFIED]),
            Finding.is_duplicate == False,  # noqa: E712
        )
        if product_id is not None:
            query = query.where(Finding.product_id == product_id)
        result = await db.execute(query)
        findings = result.scalars().all()

        # Build a set of control_ids that have at least one mapped finding
        controls_with_findings: dict[str, list[ControlFinding]] = {}
        mapped_findings_count = 0

        for finding in findings:
            mapped_controls: set[str] = set()

            # Map by CWE
            if finding.cwe and finding.cwe in CWE_TO_CONTROLS:
                for fw_id, ctrl_id in CWE_TO_CONTROLS[finding.cwe]:
                    if fw_id == framework_id:
                        mapped_controls.add(ctrl_id)

            # Map by tool type
            if finding.tool_type and finding.tool_type.upper() in TOOL_TYPE_TO_CONTROLS:
                for fw_id, ctrl_id in TOOL_TYPE_TO_CONTROLS[finding.tool_type.upper()]:
                    if fw_id == framework_id:
                        mapped_controls.add(ctrl_id)

            if mapped_controls:
                mapped_findings_count += 1
                for ctrl_id in mapped_controls:
                    controls_with_findings.setdefault(ctrl_id, []).append(
                        ControlFinding(
                            control_id=ctrl_id,
                            finding_id=finding.id,
                            finding_title=finding.title,
                            severity=finding.severity.value,
                            status=finding.status.value,
                            cwe=finding.cwe,
                        )
                    )

        # Calculate posture
        total_controls = len(framework.controls)
        control_ids_in_framework = {c.control_id for c in framework.controls}

        # A control is "covered" if we have scanner data mapping to it.
        covered_control_ids = controls_with_findings.keys() & control_ids_in_framework
        uncovered_control_ids = control_ids_in_framework - covered_control_ids

        # Covered controls with active/verified findings are "failing"
        failing_control_ids = covered_control_ids  # all covered controls have open findings
        passing_control_ids = uncovered_control_ids  # controls with no open findings pass (conservative)

        # Build gap analysis
        gaps: list[ControlGap] = []
        control_lookup = {c.control_id: c for c in framework.controls}

        for ctrl_id in sorted(uncovered_control_ids):
            ctrl = control_lookup[ctrl_id]
            gaps.append(ControlGap(
                control_id=ctrl_id,
                title=ctrl.title,
                gap_type="no_coverage",
                details=f"No scanner findings map to this control. Consider adding tool coverage for {ctrl.title}.",
            ))

        for ctrl_id in sorted(covered_control_ids):
            ctrl = control_lookup[ctrl_id]
            finding_count = len(controls_with_findings[ctrl_id])
            gaps.append(ControlGap(
                control_id=ctrl_id,
                title=ctrl.title,
                gap_type="failing",
                details=f"{finding_count} open finding(s) mapped to this control.",
            ))

        # Compliance % = passing / total * 100
        compliance_pct = (len(passing_control_ids) / total_controls * 100) if total_controls else 0.0

        return ComplianceReport(
            framework_id=framework_id,
            framework_name=framework.name,
            version=framework.version,
            total_controls=total_controls,
            controls_with_findings=len(covered_control_ids),
            passing_controls=len(passing_control_ids),
            failing_controls=len(failing_control_ids),
            compliance_percentage=round(compliance_pct, 2),
            gaps=gaps,
            mapped_findings_count=mapped_findings_count,
        )

    async def generate_overview(
        self,
        db: AsyncSession,
        product_id: Optional[int] = None,
    ) -> list[dict]:
        """Return a summary with compliance percentage per framework.

        Args:
            db: Database session.
            product_id: Optional product filter.

        Returns:
            List of dicts with framework_id, framework_name, version, and
            compliance_percentage.
        """
        overview = []
        for framework_id in FRAMEWORKS:
            report = await self.generate_report(db, framework_id, product_id)
            overview.append({
                "framework_id": report.framework_id,
                "framework_name": report.framework_name,
                "version": report.version,
                "compliance_percentage": report.compliance_percentage,
                "total_controls": report.total_controls,
                "passing_controls": report.passing_controls,
                "failing_controls": report.failing_controls,
                "mapped_findings_count": report.mapped_findings_count,
            })
        return overview

    async def generate_gap_analysis(
        self,
        db: AsyncSession,
        framework_id: str,
        product_id: Optional[int] = None,
    ) -> dict:
        """Return detailed gap analysis for a single framework.

        Args:
            db: Database session.
            framework_id: ID of the framework to evaluate.
            product_id: Optional product filter.

        Returns:
            Dict with framework metadata, gaps grouped by type, and summary
            counts.

        Raises:
            ValueError: If the framework_id is not recognised.
        """
        report = await self.generate_report(db, framework_id, product_id)

        no_coverage = [g for g in report.gaps if g.gap_type == "no_coverage"]
        failing = [g for g in report.gaps if g.gap_type == "failing"]

        return {
            "framework_id": report.framework_id,
            "framework_name": report.framework_name,
            "version": report.version,
            "total_controls": report.total_controls,
            "compliance_percentage": report.compliance_percentage,
            "no_coverage": [
                {"control_id": g.control_id, "title": g.title, "details": g.details}
                for g in no_coverage
            ],
            "failing": [
                {"control_id": g.control_id, "title": g.title, "details": g.details}
                for g in failing
            ],
            "summary": {
                "controls_without_coverage": len(no_coverage),
                "controls_failing": len(failing),
                "controls_passing": report.passing_controls,
            },
        }
