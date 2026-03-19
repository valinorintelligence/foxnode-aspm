import json
from app.parsers.registry import BaseParser


class TruffleHogParser(BaseParser):
    name = "TruffleHog"
    scan_type = "Secret Detection"
    description = "TruffleHog secret and credential detector"

    def parse(self, content: bytes) -> list[dict]:
        findings = []

        # TruffleHog outputs JSONL (one JSON object per line)
        for line in content.decode("utf-8", errors="ignore").strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector_name = item.get("DetectorName", item.get("detectorName", "unknown"))

            # Extract source metadata
            source_meta = item.get("SourceMetadata", item.get("sourceMetadata", {}))
            source_data = source_meta.get("Data", source_meta.get("data", {}))

            # Handle different source types (filesystem, git, etc.)
            file_path = ""
            line_number = None
            for source_type in source_data.values():
                if isinstance(source_type, dict):
                    file_path = source_type.get("file", source_type.get("link", ""))
                    line_number = source_type.get("line")
                    if file_path:
                        break

            # Mask the raw secret value
            raw = item.get("Raw", item.get("raw", ""))
            masked = f"{raw[:4]}****" if len(raw) > 4 else "****"

            verified = item.get("Verified", item.get("verified", False))
            severity = "critical" if verified else "high"

            findings.append({
                "title": f"Secret Detected: {detector_name}",
                "description": f"{'Verified' if verified else 'Unverified'} secret found by {detector_name} detector: {masked}",
                "severity": severity,
                "file_path": file_path,
                "line_number": line_number,
                "mitigation": "Rotate the exposed secret and remove it from the codebase",
                "unique_id": f"trufflehog-{detector_name}-{file_path}-{line_number}",
            })

        return findings
