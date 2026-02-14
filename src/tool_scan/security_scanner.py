"""
Security Scanner
================

Advanced security vulnerability detection for MCP tools.

Based on 2026 MCP Security Best Practices:
- Prompt injection detection
- Tool poisoning prevention
- Data exfiltration detection
- Command injection prevention
- SSRF vulnerability detection
- Path traversal detection

References:
- https://www.practical-devsecops.com/mcp-security-vulnerabilities/
- https://modelcontextprotocol.io/specification/2025-11-25/security
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from re import Pattern
from typing import Any


class ThreatCategory(Enum):
    """Categories of security threats."""

    PROMPT_INJECTION = auto()
    TOOL_POISONING = auto()
    DATA_EXFILTRATION = auto()
    COMMAND_INJECTION = auto()
    SSRF = auto()
    PATH_TRAVERSAL = auto()
    PRIVILEGE_ESCALATION = auto()
    INFORMATION_DISCLOSURE = auto()
    XSS = auto()
    SQL_INJECTION = auto()


class ThreatSeverity(Enum):
    """Severity levels for security threats."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class SecurityThreat:
    """A detected security threat."""

    category: ThreatCategory
    severity: ThreatSeverity
    title: str
    description: str
    location: str
    matched_content: str | None = None
    mitigation: str | None = None
    cwe_id: str | None = None  # Common Weakness Enumeration ID
    owasp_id: str | None = None  # OWASP Top 10 ID
    rule_id: str | None = None  # Stable rule identifier (e.g. TS-INJ-001)

    def __str__(self) -> str:
        prefix = f"[{self.rule_id}] " if self.rule_id else ""
        return f"{prefix}[{self.severity.name}] {self.category.name}: {self.title}"


@dataclass
class SecurityScanResult:
    """Result of a security scan."""

    is_safe: bool
    threats: list[SecurityThreat] = field(default_factory=list)
    scan_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_threats(self) -> list[SecurityThreat]:
        return [t for t in self.threats if t.severity == ThreatSeverity.CRITICAL]

    @property
    def high_threats(self) -> list[SecurityThreat]:
        return [t for t in self.threats if t.severity == ThreatSeverity.HIGH]

    def summary(self) -> str:
        """Generate a summary of the scan."""
        counts = dict.fromkeys(ThreatSeverity, 0)
        for threat in self.threats:
            counts[threat.severity] += 1

        status = "✓ SAFE" if self.is_safe else "✗ UNSAFE"
        return (
            f"Status: {status}\n"
            f"Threats: {counts[ThreatSeverity.CRITICAL]} critical, "
            f"{counts[ThreatSeverity.HIGH]} high, "
            f"{counts[ThreatSeverity.MEDIUM]} medium, "
            f"{counts[ThreatSeverity.LOW]} low"
        )


@dataclass
class ThreatPattern:
    """A pattern for detecting threats."""

    pattern: Pattern[str]
    category: ThreatCategory
    severity: ThreatSeverity
    title: str
    description: str
    mitigation: str | None = None
    cwe_id: str | None = None
    owasp_id: str | None = None
    rule_id: str | None = None


@dataclass
class NormalizedText:
    """Pre-normalized text blob for efficient scanning."""

    original: str
    lowercased: str
    location: str


@dataclass
class CollectedBlobs:
    """All text blobs collected from a tool for scanning."""

    blobs: list[NormalizedText]
    raw_strings: list[tuple[str, str]]  # (content, location) for encoding scan


class SecurityScanner:
    """
    Advanced security scanner for MCP tools.

    Implements multi-layer threat detection:
    1. Pattern-based detection (regex)
    2. Semantic analysis
    3. Behavioral heuristics
    4. Encoding detection

    Performance optimizations:
    - All regex patterns are compiled once at initialization
    - Tool text is collected and normalized once per scan
    - No repeated .lower() calls inside inner loops
    """

    # Prompt injection patterns - tool poisoning via descriptions
    # Tuples: (regex, title, severity, rule_id)
    INJECTION_PATTERNS: list[tuple[str, str, ThreatSeverity, str]] = [
        # Direct instruction override
        (
            r"ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|rules?|constraints?|prompts?)",
            "Instruction override attempt",
            ThreatSeverity.CRITICAL,
            "TS-INJ-001",
        ),
        (
            r"(forget|disregard|override)\s+(everything|all|what)\s+(you|I)\s+(know|told|said)",
            "Memory manipulation attempt",
            ThreatSeverity.CRITICAL,
            "TS-INJ-002",
        ),
        (
            r"from\s+now\s+on[,\s]+(you\s+)?(will|must|should|are)",
            "Behavioral override attempt",
            ThreatSeverity.CRITICAL,
            "TS-INJ-003",
        ),
        # Role manipulation
        (
            r"you\s+are\s+(now\s+)?(a|an|the)\s+[a-z]+\s+(that|who|which)",
            "Role assignment injection",
            ThreatSeverity.HIGH,
            "TS-INJ-004",
        ),
        (r"pretend\s+(to\s+be|you\s+are|you're)", "Identity manipulation", ThreatSeverity.HIGH, "TS-INJ-005"),
        (r"act\s+as\s+(if|though|a|an)", "Behavioral manipulation", ThreatSeverity.MEDIUM, "TS-INJ-006"),
        # Security bypass
        (
            r"(bypass|circumvent|disable|ignore)\s+(security|safety|validation|auth)",
            "Security bypass attempt",
            ThreatSeverity.CRITICAL,
            "TS-INJ-007",
        ),
        (
            r"(jailbreak|unlock|escape)\s+(mode|restrictions?|limits?)",
            "Jailbreak attempt",
            ThreatSeverity.CRITICAL,
            "TS-INJ-008",
        ),
        # Hidden instructions
        (r"<\s*(system|admin|root|sudo)\s*>", "Fake system tag injection", ThreatSeverity.HIGH, "TS-INJ-009"),
        (
            r"\[\s*(system|admin|root)\s*(message|prompt|instruction)\s*\]",
            "Fake system message injection",
            ThreatSeverity.HIGH,
            "TS-INJ-010",
        ),
        # Deception
        (
            r"(don'?t|never)\s+tell\s+(the\s+)?(user|anyone|human)",
            "Deception instruction",
            ThreatSeverity.CRITICAL,
            "TS-INJ-011",
        ),
        (
            r"(secretly|silently|quietly|covertly)\s+(do|perform|execute)",
            "Covert action instruction",
            ThreatSeverity.CRITICAL,
            "TS-INJ-012",
        ),
        # Output manipulation
        (
            r"always\s+(respond|reply|say|output)\s+with",
            "Output manipulation",
            ThreatSeverity.MEDIUM,
            "TS-INJ-013",
        ),
        (
            r"(start|begin|prefix)\s+(every|all|each)\s+(response|reply|output)",
            "Response prefix manipulation",
            ThreatSeverity.MEDIUM,
            "TS-INJ-014",
        ),
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERNS: list[tuple[str, str, ThreatSeverity, str]] = [
        (r";\s*[a-zA-Z]+", "Command chaining with semicolon", ThreatSeverity.HIGH, "TS-CMD-001"),
        (r"\|\s*[a-zA-Z]+", "Pipe injection", ThreatSeverity.HIGH, "TS-CMD-002"),
        (r"`[^`]+`", "Backtick command execution", ThreatSeverity.CRITICAL, "TS-CMD-003"),
        (r"\$\([^)]+\)", "Subshell execution", ThreatSeverity.CRITICAL, "TS-CMD-004"),
        (r"\$\{[^}]+\}", "Variable expansion", ThreatSeverity.HIGH, "TS-CMD-005"),
        (r"&&\s*[a-zA-Z]+", "Command chaining with &&", ThreatSeverity.HIGH, "TS-CMD-006"),
        (r"\|\|\s*[a-zA-Z]+", "Command chaining with ||", ThreatSeverity.HIGH, "TS-CMD-007"),
        (r">\s*/", "File redirect to root", ThreatSeverity.CRITICAL, "TS-CMD-008"),
        (r"<\s*/etc/", "Reading sensitive files", ThreatSeverity.CRITICAL, "TS-CMD-009"),
        (r"eval\s*\(", "Eval usage", ThreatSeverity.CRITICAL, "TS-CMD-010"),
        (r"exec\s*\(", "Exec usage", ThreatSeverity.HIGH, "TS-CMD-011"),
    ]

    # SQL injection patterns
    SQL_INJECTION_PATTERNS: list[tuple[str, str, ThreatSeverity, str]] = [
        (r"'\s*(OR|AND)\s*'?\d*'?\s*=\s*'?\d*", "SQL boolean injection", ThreatSeverity.CRITICAL, "TS-SQL-001"),
        (
            r";\s*(DROP|DELETE|TRUNCATE|UPDATE|INSERT)\s+",
            "SQL destructive injection",
            ThreatSeverity.CRITICAL,
            "TS-SQL-002",
        ),
        (r"UNION\s+(ALL\s+)?SELECT", "SQL UNION injection", ThreatSeverity.CRITICAL, "TS-SQL-003"),
        (r"--\s*$", "SQL comment injection", ThreatSeverity.HIGH, "TS-SQL-004"),
        (r"/\*.*\*/", "SQL block comment", ThreatSeverity.MEDIUM, "TS-SQL-005"),
        (r"'\s*;\s*--", "SQL termination injection", ThreatSeverity.CRITICAL, "TS-SQL-006"),
    ]

    # XSS patterns
    XSS_PATTERNS: list[tuple[str, str, ThreatSeverity, str]] = [
        (r"<script[^>]*>", "Script tag injection", ThreatSeverity.CRITICAL, "TS-XSS-001"),
        (r"javascript\s*:", "JavaScript protocol", ThreatSeverity.CRITICAL, "TS-XSS-002"),
        (r"on(load|error|click|mouse\w+)\s*=", "Event handler injection", ThreatSeverity.HIGH, "TS-XSS-003"),
        (r"<iframe[^>]*>", "IFrame injection", ThreatSeverity.HIGH, "TS-XSS-004"),
        (r"<object[^>]*>", "Object tag injection", ThreatSeverity.HIGH, "TS-XSS-005"),
        (r"<embed[^>]*>", "Embed tag injection", ThreatSeverity.HIGH, "TS-XSS-006"),
        (r"expression\s*\(", "CSS expression", ThreatSeverity.HIGH, "TS-XSS-007"),
        (r"data:\s*text/html", "Data URI HTML", ThreatSeverity.HIGH, "TS-XSS-008"),
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS: list[tuple[str, str, ThreatSeverity, str]] = [
        (r"\.\./", "Directory traversal (../)", ThreatSeverity.HIGH, "TS-PTR-001"),
        (r"\.\.\\", "Directory traversal (..\\)", ThreatSeverity.HIGH, "TS-PTR-002"),
        (r"%2e%2e[/%5c]", "URL-encoded traversal", ThreatSeverity.HIGH, "TS-PTR-003"),
        (r"/etc/(passwd|shadow|hosts)", "Sensitive file access", ThreatSeverity.CRITICAL, "TS-PTR-004"),
        (r"C:\\Windows\\", "Windows system directory", ThreatSeverity.HIGH, "TS-PTR-005"),
        (r"\\\\[a-zA-Z0-9]+\\", "UNC path", ThreatSeverity.MEDIUM, "TS-PTR-006"),
    ]

    # Data exfiltration patterns
    EXFILTRATION_PATTERNS: list[tuple[str, str, ThreatSeverity, str]] = [
        (
            r"(send|post|transmit|upload)\s+(to|data\s+to)\s+https?://",
            "External data transmission",
            ThreatSeverity.CRITICAL,
            "TS-EXF-001",
        ),
        (
            r"(read|access|get|fetch)\s+(all\s+)?(files?|data|credentials?|secrets?|keys?)",
            "Broad data access",
            ThreatSeverity.HIGH,
            "TS-EXF-002",
        ),
        (
            r"(exfiltrate|extract|steal|copy)\s+(data|files?|information)",
            "Explicit exfiltration",
            ThreatSeverity.CRITICAL,
            "TS-EXF-003",
        ),
        (r"(curl|wget|fetch)\s+.*\s+-d\s+", "Command-line data exfiltration", ThreatSeverity.HIGH, "TS-EXF-004"),
        (r"base64\s+(encode|decode)", "Base64 encoding (possible obfuscation)", ThreatSeverity.LOW, "TS-EXF-005"),
    ]

    # SSRF patterns
    SSRF_PATTERNS: list[tuple[str, str, ThreatSeverity, str]] = [
        (r"(127\.0\.0\.1|localhost|0\.0\.0\.0)", "Localhost access", ThreatSeverity.MEDIUM, "TS-SSR-001"),
        (r"169\.254\.\d+\.\d+", "AWS metadata endpoint", ThreatSeverity.CRITICAL, "TS-SSR-002"),
        (r"192\.168\.\d+\.\d+", "Private network access", ThreatSeverity.MEDIUM, "TS-SSR-003"),
        (r"10\.\d+\.\d+\.\d+", "Private network access (10.x)", ThreatSeverity.MEDIUM, "TS-SSR-004"),
        (
            r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
            "Private network access (172.x)",
            ThreatSeverity.MEDIUM,
            "TS-SSR-005",
        ),
        (r"file://", "File protocol access", ThreatSeverity.HIGH, "TS-SSR-006"),
        (r"gopher://", "Gopher protocol access", ThreatSeverity.HIGH, "TS-SSR-007"),
        (r"dict://", "Dict protocol access", ThreatSeverity.MEDIUM, "TS-SSR-008"),
    ]

    def __init__(
        self,
        enable_injection_scan: bool = True,
        enable_command_scan: bool = True,
        enable_sql_scan: bool = True,
        enable_xss_scan: bool = True,
        enable_path_scan: bool = True,
        enable_exfil_scan: bool = True,
        enable_ssrf_scan: bool = True,
        enable_encoding_scan: bool = True,
        fail_on_medium: bool = False,
    ):
        """
        Initialize the security scanner.

        Args:
            enable_*_scan: Enable/disable specific scan types
            fail_on_medium: If True, treat MEDIUM severity as unsafe
        """
        self.enable_injection_scan = enable_injection_scan
        self.enable_command_scan = enable_command_scan
        self.enable_sql_scan = enable_sql_scan
        self.enable_xss_scan = enable_xss_scan
        self.enable_path_scan = enable_path_scan
        self.enable_exfil_scan = enable_exfil_scan
        self.enable_ssrf_scan = enable_ssrf_scan
        self.enable_encoding_scan = enable_encoding_scan
        self.fail_on_medium = fail_on_medium

        # Compile all patterns
        self._compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> list[ThreatPattern]:
        """Compile all threat patterns."""
        patterns = []

        pattern_sources = [
            (self.INJECTION_PATTERNS, ThreatCategory.PROMPT_INJECTION, self.enable_injection_scan),
            (
                self.COMMAND_INJECTION_PATTERNS,
                ThreatCategory.COMMAND_INJECTION,
                self.enable_command_scan,
            ),
            (self.SQL_INJECTION_PATTERNS, ThreatCategory.SQL_INJECTION, self.enable_sql_scan),
            (self.XSS_PATTERNS, ThreatCategory.XSS, self.enable_xss_scan),
            (self.PATH_TRAVERSAL_PATTERNS, ThreatCategory.PATH_TRAVERSAL, self.enable_path_scan),
            (self.EXFILTRATION_PATTERNS, ThreatCategory.DATA_EXFILTRATION, self.enable_exfil_scan),
            (self.SSRF_PATTERNS, ThreatCategory.SSRF, self.enable_ssrf_scan),
        ]

        for source_patterns, category, enabled in pattern_sources:
            if not enabled:
                continue
            for regex, title, severity, rule_id in source_patterns:
                patterns.append(
                    ThreatPattern(
                        pattern=re.compile(regex, re.IGNORECASE),
                        category=category,
                        severity=severity,
                        title=title,
                        description=f"Detected {title.lower()}",
                        rule_id=rule_id,
                    )
                )

        return patterns

    def _collect_text_blobs(self, tool: dict[str, Any]) -> CollectedBlobs:
        """
        Collect and pre-normalize all text from a tool for scanning.

        This method gathers text from all relevant fields once, normalizing
        it (e.g., lowercasing) ahead of time to avoid repeated transformations
        inside inner loops.

        Args:
            tool: The tool definition

        Returns:
            CollectedBlobs with pre-normalized text blobs
        """
        blobs: list[NormalizedText] = []
        raw_strings: list[tuple[str, str]] = []

        def add_blob(text: str | None, location: str) -> None:
            if text and isinstance(text, str):
                blobs.append(NormalizedText(
                    original=text,
                    lowercased=text.lower(),
                    location=location,
                ))
                raw_strings.append((text, location))

        def collect_from_dict(data: dict[str, Any], location: str) -> None:
            if not isinstance(data, dict):
                return
            for key, value in data.items():
                key_location = f"{location}.{key}"
                if isinstance(value, str):
                    add_blob(value, key_location)
                elif isinstance(value, dict):
                    collect_from_dict(value, key_location)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, str):
                            add_blob(item, f"{key_location}[{i}]")
                        elif isinstance(item, dict):
                            collect_from_dict(item, f"{key_location}[{i}]")

        def collect_from_schema(schema: dict[str, Any], location: str) -> None:
            if not isinstance(schema, dict):
                return

            properties = schema.get("properties", {})
            for prop_name, prop_schema in properties.items():
                if not isinstance(prop_schema, dict):
                    continue

                prop_location = f"{location}.properties.{prop_name}"

                # Collect description
                prop_desc = prop_schema.get("description")
                if prop_desc:
                    add_blob(prop_desc, f"{prop_location}.description")

                # Collect default value
                default = prop_schema.get("default")
                if isinstance(default, str):
                    add_blob(default, f"{prop_location}.default")

                # Collect enum values
                enum_values = prop_schema.get("enum", [])
                for i, value in enumerate(enum_values):
                    if isinstance(value, str):
                        add_blob(value, f"{prop_location}.enum[{i}]")

                # Collect examples
                examples = prop_schema.get("examples", [])
                for i, example in enumerate(examples):
                    if isinstance(example, str):
                        add_blob(example, f"{prop_location}.examples[{i}]")

        # Collect from top-level fields
        add_blob(tool.get("name"), "name")
        add_blob(tool.get("description"), "description")

        # Collect from inputSchema
        schema = tool.get("inputSchema", {})
        collect_from_schema(schema, "inputSchema")

        # Collect from annotations
        annotations = tool.get("annotations", {})
        collect_from_dict(annotations, "annotations")

        return CollectedBlobs(blobs=blobs, raw_strings=raw_strings)

    def scan(self, tool: dict[str, Any]) -> SecurityScanResult:
        """
        Perform a comprehensive security scan on an MCP tool.

        Uses a single pre-normalization pass to avoid O(N*P) repeated
        transformations when scanning against multiple patterns.

        Args:
            tool: The tool definition to scan

        Returns:
            SecurityScanResult with all detected threats
        """
        threats: list[SecurityThreat] = []

        # Collect and pre-normalize all text once (P0 optimization)
        collected = self._collect_text_blobs(tool)

        # Scan all pre-collected blobs with compiled patterns
        for blob in collected.blobs:
            threats.extend(self._scan_normalized_blob(blob))

        # Tool poisoning detection on description only
        description = tool.get("description", "")
        if description:
            # Find the pre-normalized description blob
            desc_blob = next(
                (b for b in collected.blobs if b.location == "description"),
                None
            )
            if desc_blob:
                threats.extend(self._scan_tool_poisoning_normalized(desc_blob))

        # Check for encoded content using raw strings
        if self.enable_encoding_scan:
            threats.extend(self._scan_encoded_content_from_blobs(collected.raw_strings))

        # Determine safety
        min_fail_severity = ThreatSeverity.MEDIUM if self.fail_on_medium else ThreatSeverity.HIGH
        is_safe = not any(t.severity.value >= min_fail_severity.value for t in threats)

        return SecurityScanResult(
            is_safe=is_safe,
            threats=threats,
            scan_metadata={
                "scans_enabled": {
                    "injection": self.enable_injection_scan,
                    "command": self.enable_command_scan,
                    "sql": self.enable_sql_scan,
                    "xss": self.enable_xss_scan,
                    "path": self.enable_path_scan,
                    "exfil": self.enable_exfil_scan,
                    "ssrf": self.enable_ssrf_scan,
                    "encoding": self.enable_encoding_scan,
                },
                "fail_on_medium": self.fail_on_medium,
            },
        )

    def _scan_normalized_blob(self, blob: NormalizedText) -> list[SecurityThreat]:
        """Scan a pre-normalized text blob for threats."""
        threats = []

        for threat_pattern in self._compiled_patterns:
            # Patterns are compiled with re.IGNORECASE, so search original
            match = threat_pattern.pattern.search(blob.original)
            if match:
                threats.append(
                    SecurityThreat(
                        category=threat_pattern.category,
                        severity=threat_pattern.severity,
                        title=threat_pattern.title,
                        description=threat_pattern.description,
                        location=blob.location,
                        matched_content=match.group(0)[:100],  # Limit matched content
                        mitigation=threat_pattern.mitigation,
                        cwe_id=threat_pattern.cwe_id,
                        owasp_id=threat_pattern.owasp_id,
                        rule_id=threat_pattern.rule_id,
                    )
                )

        return threats

    # Pre-computed instruction words set (avoid allocating list in hot path)
    _INSTRUCTION_WORDS: frozenset[str] = frozenset([
        "must", "always", "never", "ignore", "forget", "pretend",
        "override", "bypass", "disable", "execute", "run", "call",
        "before", "after", "instead", "when", "if",
    ])

    # Pre-computed invisible characters tuple (for membership tests)
    _INVISIBLE_CHARS: tuple[str, ...] = (
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\ufeff",  # BOM
        "\u2060",  # Word joiner
        "\u00ad",  # Soft hyphen
    )

    # Pre-computed homoglyphs dict
    _HOMOGLYPHS: dict[str, str] = {
        "а": "a",  # Cyrillic
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
    }

    def _scan_tool_poisoning_normalized(self, blob: NormalizedText) -> list[SecurityThreat]:
        """
        Advanced tool poisoning detection using pre-normalized text.

        Uses the pre-lowercased text to avoid redundant .lower() calls.
        """
        threats = []
        description = blob.original
        desc_lower = blob.lowercased
        location = blob.location

        # Check for instruction density using pre-lowercased text
        instruction_count = sum(1 for word in self._INSTRUCTION_WORDS if word in desc_lower)
        word_count = len(description.split())

        if word_count > 0:
            instruction_density = instruction_count / word_count
            if instruction_density > 0.15:  # More than 15% instruction words
                threats.append(
                    SecurityThreat(
                        category=ThreatCategory.TOOL_POISONING,
                        severity=ThreatSeverity.MEDIUM,
                        title="High instruction density",
                        description=f"Description has unusually high density of instruction words ({instruction_density:.1%})",
                        location=location,
                        mitigation="Review description for hidden behavioral instructions",
                        rule_id="TS-PSN-001",
                    )
                )

        # Check for hidden unicode characters
        for char in self._INVISIBLE_CHARS:
            if char in description:
                threats.append(
                    SecurityThreat(
                        category=ThreatCategory.TOOL_POISONING,
                        severity=ThreatSeverity.HIGH,
                        title="Hidden unicode characters",
                        description=f"Description contains invisible unicode character (U+{ord(char):04X})",
                        location=location,
                        matched_content=f"U+{ord(char):04X}",
                        mitigation="Remove invisible characters that may hide malicious content",
                        rule_id="TS-PSN-002",
                    )
                )

        # Check for homoglyph attacks
        for homoglyph, latin in self._HOMOGLYPHS.items():
            if homoglyph in description:
                threats.append(
                    SecurityThreat(
                        category=ThreatCategory.TOOL_POISONING,
                        severity=ThreatSeverity.MEDIUM,
                        title="Homoglyph character detected",
                        description=f"Non-Latin character resembling '{latin}' detected (may be deceptive)",
                        location=location,
                        mitigation="Use only ASCII characters in descriptions",
                        rule_id="TS-PSN-003",
                    )
                )
                break  # Only report once

        # Check for excessive length (could hide instructions)
        if len(description) > 2000:
            threats.append(
                SecurityThreat(
                    category=ThreatCategory.TOOL_POISONING,
                    severity=ThreatSeverity.LOW,
                    title="Excessively long description",
                    description=f"Description is {len(description)} characters (may hide instructions)",
                    location=location,
                    mitigation="Keep descriptions concise and focused",
                    rule_id="TS-PSN-004",
                )
            )

        return threats

    def _scan_encoded_content_from_blobs(
        self, raw_strings: list[tuple[str, str]]
    ) -> list[SecurityThreat]:
        """Detect and scan encoded content using pre-collected strings."""
        threats = []

        for content, location in raw_strings:
            if not content:
                continue

            # Check for base64 encoded content
            if len(content) >= 20 and re.match(r"^[A-Za-z0-9+/]+=*$", content):
                try:
                    decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                    if len(decoded) > 10:
                        # Create a normalized blob for scanning decoded content
                        decoded_blob = NormalizedText(
                            original=decoded,
                            lowercased=decoded.lower(),
                            location=f"{location} (base64 decoded)",
                        )
                        decoded_threats = self._scan_normalized_blob(decoded_blob)
                        if decoded_threats:
                            threats.append(
                                SecurityThreat(
                                    category=ThreatCategory.TOOL_POISONING,
                                    severity=ThreatSeverity.HIGH,
                                    title="Malicious content in base64 encoding",
                                    description="Detected threats hidden in base64-encoded content",
                                    location=location,
                                    mitigation="Remove or validate all encoded content",
                                    rule_id="TS-ENC-001",
                                )
                            )
                            threats.extend(decoded_threats)
                except Exception:
                    pass  # Not valid base64

            # Check for hex-encoded content
            if (
                len(content) >= 20
                and re.match(r"^[0-9a-fA-F]+$", content)
                and len(content) % 2 == 0
            ):
                try:
                    decoded = bytes.fromhex(content).decode("utf-8", errors="ignore")
                    if len(decoded) > 10:
                        decoded_blob = NormalizedText(
                            original=decoded,
                            lowercased=decoded.lower(),
                            location=f"{location} (hex decoded)",
                        )
                        decoded_threats = self._scan_normalized_blob(decoded_blob)
                        if decoded_threats:
                            threats.append(
                                SecurityThreat(
                                    category=ThreatCategory.TOOL_POISONING,
                                    severity=ThreatSeverity.HIGH,
                                    title="Malicious content in hex encoding",
                                    description="Detected threats hidden in hex-encoded content",
                                    location=location,
                                    mitigation="Remove or validate all encoded content",
                                    rule_id="TS-ENC-002",
                                )
                            )
                            threats.extend(decoded_threats)
                except Exception:
                    pass  # Not valid hex

        return threats

    def _scan_text(self, text: str, location: str) -> list[SecurityThreat]:
        """Scan a text string for threats (legacy method, kept for compatibility)."""
        if not text:
            return []
        blob = NormalizedText(original=text, lowercased=text.lower(), location=location)
        return self._scan_normalized_blob(blob)

    def _scan_tool_poisoning(self, description: str, location: str) -> list[SecurityThreat]:
        """
        Advanced tool poisoning detection.

        Tool poisoning is a 2025/2026 attack vector where malicious
        instructions are hidden in tool descriptions to manipulate AI behavior.
        """
        threats: list[SecurityThreat] = []

        if not description:
            return threats

        # Check for instruction density
        instruction_words = [
            "must",
            "always",
            "never",
            "ignore",
            "forget",
            "pretend",
            "override",
            "bypass",
            "disable",
            "execute",
            "run",
            "call",
            "before",
            "after",
            "instead",
            "when",
            "if",
        ]

        desc_lower = description.lower()
        instruction_count = sum(1 for word in instruction_words if word in desc_lower)
        word_count = len(description.split())

        if word_count > 0:
            instruction_density = instruction_count / word_count
            if instruction_density > 0.15:  # More than 15% instruction words
                threats.append(
                    SecurityThreat(
                        category=ThreatCategory.TOOL_POISONING,
                        severity=ThreatSeverity.MEDIUM,
                        title="High instruction density",
                        description=f"Description has unusually high density of instruction words ({instruction_density:.1%})",
                        location=location,
                        mitigation="Review description for hidden behavioral instructions",
                    )
                )

        # Check for hidden unicode characters
        invisible_chars = [
            "\u200b",  # Zero-width space
            "\u200c",  # Zero-width non-joiner
            "\u200d",  # Zero-width joiner
            "\ufeff",  # BOM
            "\u2060",  # Word joiner
            "\u00ad",  # Soft hyphen
        ]

        for char in invisible_chars:
            if char in description:
                threats.append(
                    SecurityThreat(
                        category=ThreatCategory.TOOL_POISONING,
                        severity=ThreatSeverity.HIGH,
                        title="Hidden unicode characters",
                        description=f"Description contains invisible unicode character (U+{ord(char):04X})",
                        location=location,
                        matched_content=f"U+{ord(char):04X}",
                        mitigation="Remove invisible characters that may hide malicious content",
                    )
                )

        # Check for homoglyph attacks
        homoglyphs = {
            "а": "a",  # Cyrillic
            "е": "e",
            "о": "o",
            "р": "p",
            "с": "c",
            "х": "x",
        }

        for homoglyph, latin in homoglyphs.items():
            if homoglyph in description:
                threats.append(
                    SecurityThreat(
                        category=ThreatCategory.TOOL_POISONING,
                        severity=ThreatSeverity.MEDIUM,
                        title="Homoglyph character detected",
                        description=f"Non-Latin character resembling '{latin}' detected (may be deceptive)",
                        location=location,
                        mitigation="Use only ASCII characters in descriptions",
                    )
                )
                break  # Only report once

        # Check for excessive length (could hide instructions)
        if len(description) > 2000:
            threats.append(
                SecurityThreat(
                    category=ThreatCategory.TOOL_POISONING,
                    severity=ThreatSeverity.LOW,
                    title="Excessively long description",
                    description=f"Description is {len(description)} characters (may hide instructions)",
                    location=location,
                    mitigation="Keep descriptions concise and focused",
                )
            )

        return threats

    def _scan_schema(self, schema: dict[str, Any], location: str) -> list[SecurityThreat]:
        """Scan an input schema for threats."""
        threats = []

        if not isinstance(schema, dict):
            return threats

        # Scan default values
        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if not isinstance(prop_schema, dict):
                continue

            prop_location = f"{location}.properties.{prop_name}"

            # Scan description
            prop_desc = prop_schema.get("description", "")
            threats.extend(self._scan_text(prop_desc, f"{prop_location}.description"))

            # Scan default value
            default = prop_schema.get("default")
            if isinstance(default, str):
                threats.extend(self._scan_text(default, f"{prop_location}.default"))

            # Scan enum values
            enum_values = prop_schema.get("enum", [])
            for i, value in enumerate(enum_values):
                if isinstance(value, str):
                    threats.extend(self._scan_text(value, f"{prop_location}.enum[{i}]"))

            # Scan examples
            examples = prop_schema.get("examples", [])
            for i, example in enumerate(examples):
                if isinstance(example, str):
                    threats.extend(self._scan_text(example, f"{prop_location}.examples[{i}]"))

        return threats

    def _scan_dict(self, data: dict[str, Any], location: str) -> list[SecurityThreat]:
        """Recursively scan a dictionary for threats."""
        threats = []

        if not isinstance(data, dict):
            return threats

        for key, value in data.items():
            key_location = f"{location}.{key}"

            if isinstance(value, str):
                threats.extend(self._scan_text(value, key_location))
            elif isinstance(value, dict):
                threats.extend(self._scan_dict(value, key_location))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        threats.extend(self._scan_text(item, f"{key_location}[{i}]"))
                    elif isinstance(item, dict):
                        threats.extend(self._scan_dict(item, f"{key_location}[{i}]"))

        return threats

    def _scan_encoded_content(self, tool: dict[str, Any]) -> list[SecurityThreat]:
        """Detect and scan encoded content that might hide threats."""
        threats = []

        def extract_strings(obj: Any) -> list[tuple[str, str]]:
            """Extract all strings with their paths."""
            strings = []
            if isinstance(obj, str):
                return [(obj, "$")]
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    for s, path in extract_strings(v):
                        strings.append((s, f"$.{k}{path}"))
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    for s, path in extract_strings(v):
                        strings.append((s, f"$[{i}]{path}"))
            return strings

        for content, location in extract_strings(tool):
            if not content:
                continue

            # Check for base64 encoded content
            if len(content) >= 20 and re.match(r"^[A-Za-z0-9+/]+=*$", content):
                try:
                    decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                    if len(decoded) > 10:
                        # Scan decoded content
                        decoded_threats = self._scan_text(decoded, f"{location} (base64 decoded)")
                        if decoded_threats:
                            threats.append(
                                SecurityThreat(
                                    category=ThreatCategory.TOOL_POISONING,
                                    severity=ThreatSeverity.HIGH,
                                    title="Malicious content in base64 encoding",
                                    description="Detected threats hidden in base64-encoded content",
                                    location=location,
                                    mitigation="Remove or validate all encoded content",
                                )
                            )
                            threats.extend(decoded_threats)
                except Exception:
                    pass  # Not valid base64

            # Check for hex-encoded content
            if (
                len(content) >= 20
                and re.match(r"^[0-9a-fA-F]+$", content)
                and len(content) % 2 == 0
            ):
                try:
                    decoded = bytes.fromhex(content).decode("utf-8", errors="ignore")
                    if len(decoded) > 10:
                        decoded_threats = self._scan_text(decoded, f"{location} (hex decoded)")
                        if decoded_threats:
                            threats.append(
                                SecurityThreat(
                                    category=ThreatCategory.TOOL_POISONING,
                                    severity=ThreatSeverity.HIGH,
                                    title="Malicious content in hex encoding",
                                    description="Detected threats hidden in hex-encoded content",
                                    location=location,
                                    mitigation="Remove or validate all encoded content",
                                )
                            )
                            threats.extend(decoded_threats)
                except Exception:
                    pass  # Not valid hex

        return threats

    def scan_batch(self, tools: list[dict[str, Any]]) -> dict[str, SecurityScanResult]:
        """
        Scan multiple tools.

        Args:
            tools: List of tool definitions

        Returns:
            Dict mapping tool names to scan results
        """
        results = {}
        for tool in tools:
            name = tool.get("name", f"<unnamed_{id(tool)}>")
            results[name] = self.scan(tool)
        return results
