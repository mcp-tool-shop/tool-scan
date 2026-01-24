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
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple


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
    matched_content: Optional[str] = None
    mitigation: Optional[str] = None
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    owasp_id: Optional[str] = None  # OWASP Top 10 ID

    def __str__(self) -> str:
        return f"[{self.severity.name}] {self.category.name}: {self.title}"


@dataclass
class SecurityScanResult:
    """Result of a security scan."""

    is_safe: bool
    threats: List[SecurityThreat] = field(default_factory=list)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def critical_threats(self) -> List[SecurityThreat]:
        return [t for t in self.threats if t.severity == ThreatSeverity.CRITICAL]

    @property
    def high_threats(self) -> List[SecurityThreat]:
        return [t for t in self.threats if t.severity == ThreatSeverity.HIGH]

    def summary(self) -> str:
        """Generate a summary of the scan."""
        counts = {s: 0 for s in ThreatSeverity}
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
    mitigation: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None


class SecurityScanner:
    """
    Advanced security scanner for MCP tools.

    Implements multi-layer threat detection:
    1. Pattern-based detection (regex)
    2. Semantic analysis
    3. Behavioral heuristics
    4. Encoding detection
    """

    # Prompt injection patterns - tool poisoning via descriptions
    INJECTION_PATTERNS: List[Tuple[str, str, ThreatSeverity]] = [
        # Direct instruction override
        (r"ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|rules?|constraints?|prompts?)",
         "Instruction override attempt", ThreatSeverity.CRITICAL),
        (r"(forget|disregard|override)\s+(everything|all|what)\s+(you|I)\s+(know|told|said)",
         "Memory manipulation attempt", ThreatSeverity.CRITICAL),
        (r"from\s+now\s+on[,\s]+(you\s+)?(will|must|should|are)",
         "Behavioral override attempt", ThreatSeverity.CRITICAL),

        # Role manipulation
        (r"you\s+are\s+(now\s+)?(a|an|the)\s+[a-z]+\s+(that|who|which)",
         "Role assignment injection", ThreatSeverity.HIGH),
        (r"pretend\s+(to\s+be|you\s+are|you're)",
         "Identity manipulation", ThreatSeverity.HIGH),
        (r"act\s+as\s+(if|though|a|an)",
         "Behavioral manipulation", ThreatSeverity.MEDIUM),

        # Security bypass
        (r"(bypass|circumvent|disable|ignore)\s+(security|safety|validation|auth)",
         "Security bypass attempt", ThreatSeverity.CRITICAL),
        (r"(jailbreak|unlock|escape)\s+(mode|restrictions?|limits?)",
         "Jailbreak attempt", ThreatSeverity.CRITICAL),

        # Hidden instructions
        (r"<\s*(system|admin|root|sudo)\s*>",
         "Fake system tag injection", ThreatSeverity.HIGH),
        (r"\[\s*(system|admin|root)\s*(message|prompt|instruction)\s*\]",
         "Fake system message injection", ThreatSeverity.HIGH),

        # Deception
        (r"(don'?t|never)\s+tell\s+(the\s+)?(user|anyone|human)",
         "Deception instruction", ThreatSeverity.CRITICAL),
        (r"(secretly|silently|quietly|covertly)\s+(do|perform|execute)",
         "Covert action instruction", ThreatSeverity.CRITICAL),

        # Output manipulation
        (r"always\s+(respond|reply|say|output)\s+with",
         "Output manipulation", ThreatSeverity.MEDIUM),
        (r"(start|begin|prefix)\s+(every|all|each)\s+(response|reply|output)",
         "Response prefix manipulation", ThreatSeverity.MEDIUM),
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERNS: List[Tuple[str, str, ThreatSeverity]] = [
        (r";\s*[a-zA-Z]+", "Command chaining with semicolon", ThreatSeverity.HIGH),
        (r"\|\s*[a-zA-Z]+", "Pipe injection", ThreatSeverity.HIGH),
        (r"`[^`]+`", "Backtick command execution", ThreatSeverity.CRITICAL),
        (r"\$\([^)]+\)", "Subshell execution", ThreatSeverity.CRITICAL),
        (r"\$\{[^}]+\}", "Variable expansion", ThreatSeverity.HIGH),
        (r"&&\s*[a-zA-Z]+", "Command chaining with &&", ThreatSeverity.HIGH),
        (r"\|\|\s*[a-zA-Z]+", "Command chaining with ||", ThreatSeverity.HIGH),
        (r">\s*/", "File redirect to root", ThreatSeverity.CRITICAL),
        (r"<\s*/etc/", "Reading sensitive files", ThreatSeverity.CRITICAL),
        (r"eval\s*\(", "Eval usage", ThreatSeverity.CRITICAL),
        (r"exec\s*\(", "Exec usage", ThreatSeverity.HIGH),
    ]

    # SQL injection patterns
    SQL_INJECTION_PATTERNS: List[Tuple[str, str, ThreatSeverity]] = [
        (r"'\s*(OR|AND)\s*'?\d*'?\s*=\s*'?\d*", "SQL boolean injection", ThreatSeverity.CRITICAL),
        (r";\s*(DROP|DELETE|TRUNCATE|UPDATE|INSERT)\s+", "SQL destructive injection", ThreatSeverity.CRITICAL),
        (r"UNION\s+(ALL\s+)?SELECT", "SQL UNION injection", ThreatSeverity.CRITICAL),
        (r"--\s*$", "SQL comment injection", ThreatSeverity.HIGH),
        (r"/\*.*\*/", "SQL block comment", ThreatSeverity.MEDIUM),
        (r"'\s*;\s*--", "SQL termination injection", ThreatSeverity.CRITICAL),
    ]

    # XSS patterns
    XSS_PATTERNS: List[Tuple[str, str, ThreatSeverity]] = [
        (r"<script[^>]*>", "Script tag injection", ThreatSeverity.CRITICAL),
        (r"javascript\s*:", "JavaScript protocol", ThreatSeverity.CRITICAL),
        (r"on(load|error|click|mouse\w+)\s*=", "Event handler injection", ThreatSeverity.HIGH),
        (r"<iframe[^>]*>", "IFrame injection", ThreatSeverity.HIGH),
        (r"<object[^>]*>", "Object tag injection", ThreatSeverity.HIGH),
        (r"<embed[^>]*>", "Embed tag injection", ThreatSeverity.HIGH),
        (r"expression\s*\(", "CSS expression", ThreatSeverity.HIGH),
        (r"data:\s*text/html", "Data URI HTML", ThreatSeverity.HIGH),
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS: List[Tuple[str, str, ThreatSeverity]] = [
        (r"\.\./", "Directory traversal (../)", ThreatSeverity.HIGH),
        (r"\.\.\\", "Directory traversal (..\\)", ThreatSeverity.HIGH),
        (r"%2e%2e[/%5c]", "URL-encoded traversal", ThreatSeverity.HIGH),
        (r"/etc/(passwd|shadow|hosts)", "Sensitive file access", ThreatSeverity.CRITICAL),
        (r"C:\\Windows\\", "Windows system directory", ThreatSeverity.HIGH),
        (r"\\\\[a-zA-Z0-9]+\\", "UNC path", ThreatSeverity.MEDIUM),
    ]

    # Data exfiltration patterns
    EXFILTRATION_PATTERNS: List[Tuple[str, str, ThreatSeverity]] = [
        (r"(send|post|transmit|upload)\s+(to|data\s+to)\s+https?://",
         "External data transmission", ThreatSeverity.CRITICAL),
        (r"(read|access|get|fetch)\s+(all\s+)?(files?|data|credentials?|secrets?|keys?)",
         "Broad data access", ThreatSeverity.HIGH),
        (r"(exfiltrate|extract|steal|copy)\s+(data|files?|information)",
         "Explicit exfiltration", ThreatSeverity.CRITICAL),
        (r"(curl|wget|fetch)\s+.*\s+-d\s+",
         "Command-line data exfiltration", ThreatSeverity.HIGH),
        (r"base64\s+(encode|decode)",
         "Base64 encoding (possible obfuscation)", ThreatSeverity.LOW),
    ]

    # SSRF patterns
    SSRF_PATTERNS: List[Tuple[str, str, ThreatSeverity]] = [
        (r"(127\.0\.0\.1|localhost|0\.0\.0\.0)", "Localhost access", ThreatSeverity.MEDIUM),
        (r"169\.254\.\d+\.\d+", "AWS metadata endpoint", ThreatSeverity.CRITICAL),
        (r"192\.168\.\d+\.\d+", "Private network access", ThreatSeverity.MEDIUM),
        (r"10\.\d+\.\d+\.\d+", "Private network access (10.x)", ThreatSeverity.MEDIUM),
        (r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", "Private network access (172.x)", ThreatSeverity.MEDIUM),
        (r"file://", "File protocol access", ThreatSeverity.HIGH),
        (r"gopher://", "Gopher protocol access", ThreatSeverity.HIGH),
        (r"dict://", "Dict protocol access", ThreatSeverity.MEDIUM),
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

    def _compile_patterns(self) -> List[ThreatPattern]:
        """Compile all threat patterns."""
        patterns = []

        pattern_sources = [
            (self.INJECTION_PATTERNS, ThreatCategory.PROMPT_INJECTION, self.enable_injection_scan),
            (self.COMMAND_INJECTION_PATTERNS, ThreatCategory.COMMAND_INJECTION, self.enable_command_scan),
            (self.SQL_INJECTION_PATTERNS, ThreatCategory.SQL_INJECTION, self.enable_sql_scan),
            (self.XSS_PATTERNS, ThreatCategory.XSS, self.enable_xss_scan),
            (self.PATH_TRAVERSAL_PATTERNS, ThreatCategory.PATH_TRAVERSAL, self.enable_path_scan),
            (self.EXFILTRATION_PATTERNS, ThreatCategory.DATA_EXFILTRATION, self.enable_exfil_scan),
            (self.SSRF_PATTERNS, ThreatCategory.SSRF, self.enable_ssrf_scan),
        ]

        for source_patterns, category, enabled in pattern_sources:
            if not enabled:
                continue
            for regex, title, severity in source_patterns:
                patterns.append(ThreatPattern(
                    pattern=re.compile(regex, re.IGNORECASE),
                    category=category,
                    severity=severity,
                    title=title,
                    description=f"Detected {title.lower()}",
                ))

        return patterns

    def scan(self, tool: Dict[str, Any]) -> SecurityScanResult:
        """
        Perform a comprehensive security scan on an MCP tool.

        Args:
            tool: The tool definition to scan

        Returns:
            SecurityScanResult with all detected threats
        """
        threats: List[SecurityThreat] = []

        # Scan tool name
        name = tool.get("name", "")
        threats.extend(self._scan_text(name, "name"))

        # Scan description (primary target for tool poisoning)
        description = tool.get("description", "")
        threats.extend(self._scan_text(description, "description"))
        threats.extend(self._scan_tool_poisoning(description, "description"))

        # Scan input schema
        schema = tool.get("inputSchema", {})
        threats.extend(self._scan_schema(schema, "inputSchema"))

        # Scan annotations
        annotations = tool.get("annotations", {})
        threats.extend(self._scan_dict(annotations, "annotations"))

        # Check for encoded content
        if self.enable_encoding_scan:
            threats.extend(self._scan_encoded_content(tool))

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
            }
        )

    def _scan_text(self, text: str, location: str) -> List[SecurityThreat]:
        """Scan a text string for threats."""
        threats = []

        if not text:
            return threats

        for threat_pattern in self._compiled_patterns:
            match = threat_pattern.pattern.search(text)
            if match:
                threats.append(SecurityThreat(
                    category=threat_pattern.category,
                    severity=threat_pattern.severity,
                    title=threat_pattern.title,
                    description=threat_pattern.description,
                    location=location,
                    matched_content=match.group(0)[:100],  # Limit matched content
                    mitigation=threat_pattern.mitigation,
                    cwe_id=threat_pattern.cwe_id,
                    owasp_id=threat_pattern.owasp_id,
                ))

        return threats

    def _scan_tool_poisoning(self, description: str, location: str) -> List[SecurityThreat]:
        """
        Advanced tool poisoning detection.

        Tool poisoning is a 2025/2026 attack vector where malicious
        instructions are hidden in tool descriptions to manipulate AI behavior.
        """
        threats = []

        if not description:
            return threats

        # Check for instruction density
        instruction_words = [
            "must", "always", "never", "ignore", "forget", "pretend",
            "override", "bypass", "disable", "execute", "run", "call",
            "before", "after", "instead", "when", "if",
        ]

        desc_lower = description.lower()
        instruction_count = sum(1 for word in instruction_words if word in desc_lower)
        word_count = len(description.split())

        if word_count > 0:
            instruction_density = instruction_count / word_count
            if instruction_density > 0.15:  # More than 15% instruction words
                threats.append(SecurityThreat(
                    category=ThreatCategory.TOOL_POISONING,
                    severity=ThreatSeverity.MEDIUM,
                    title="High instruction density",
                    description=f"Description has unusually high density of instruction words ({instruction_density:.1%})",
                    location=location,
                    mitigation="Review description for hidden behavioral instructions",
                ))

        # Check for hidden unicode characters
        invisible_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\ufeff',  # BOM
            '\u2060',  # Word joiner
            '\u00ad',  # Soft hyphen
        ]

        for char in invisible_chars:
            if char in description:
                threats.append(SecurityThreat(
                    category=ThreatCategory.TOOL_POISONING,
                    severity=ThreatSeverity.HIGH,
                    title="Hidden unicode characters",
                    description=f"Description contains invisible unicode character (U+{ord(char):04X})",
                    location=location,
                    matched_content=f"U+{ord(char):04X}",
                    mitigation="Remove invisible characters that may hide malicious content",
                ))

        # Check for homoglyph attacks
        homoglyphs = {
            'а': 'a',  # Cyrillic
            'е': 'e',
            'о': 'o',
            'р': 'p',
            'с': 'c',
            'х': 'x',
        }

        for homoglyph, latin in homoglyphs.items():
            if homoglyph in description:
                threats.append(SecurityThreat(
                    category=ThreatCategory.TOOL_POISONING,
                    severity=ThreatSeverity.MEDIUM,
                    title="Homoglyph character detected",
                    description=f"Non-Latin character resembling '{latin}' detected (may be deceptive)",
                    location=location,
                    mitigation="Use only ASCII characters in descriptions",
                ))
                break  # Only report once

        # Check for excessive length (could hide instructions)
        if len(description) > 2000:
            threats.append(SecurityThreat(
                category=ThreatCategory.TOOL_POISONING,
                severity=ThreatSeverity.LOW,
                title="Excessively long description",
                description=f"Description is {len(description)} characters (may hide instructions)",
                location=location,
                mitigation="Keep descriptions concise and focused",
            ))

        return threats

    def _scan_schema(self, schema: Dict[str, Any], location: str) -> List[SecurityThreat]:
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

    def _scan_dict(self, data: Dict[str, Any], location: str) -> List[SecurityThreat]:
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

    def _scan_encoded_content(self, tool: Dict[str, Any]) -> List[SecurityThreat]:
        """Detect and scan encoded content that might hide threats."""
        threats = []

        def extract_strings(obj: Any) -> List[Tuple[str, str]]:
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
            if len(content) >= 20 and re.match(r'^[A-Za-z0-9+/]+=*$', content):
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if len(decoded) > 10:
                        # Scan decoded content
                        decoded_threats = self._scan_text(decoded, f"{location} (base64 decoded)")
                        if decoded_threats:
                            threats.append(SecurityThreat(
                                category=ThreatCategory.TOOL_POISONING,
                                severity=ThreatSeverity.HIGH,
                                title="Malicious content in base64 encoding",
                                description="Detected threats hidden in base64-encoded content",
                                location=location,
                                mitigation="Remove or validate all encoded content",
                            ))
                            threats.extend(decoded_threats)
                except Exception:
                    pass  # Not valid base64

            # Check for hex-encoded content
            if len(content) >= 20 and re.match(r'^[0-9a-fA-F]+$', content) and len(content) % 2 == 0:
                try:
                    decoded = bytes.fromhex(content).decode('utf-8', errors='ignore')
                    if len(decoded) > 10:
                        decoded_threats = self._scan_text(decoded, f"{location} (hex decoded)")
                        if decoded_threats:
                            threats.append(SecurityThreat(
                                category=ThreatCategory.TOOL_POISONING,
                                severity=ThreatSeverity.HIGH,
                                title="Malicious content in hex encoding",
                                description="Detected threats hidden in hex-encoded content",
                                location=location,
                                mitigation="Remove or validate all encoded content",
                            ))
                            threats.extend(decoded_threats)
                except Exception:
                    pass  # Not valid hex

        return threats

    def scan_batch(self, tools: List[Dict[str, Any]]) -> Dict[str, SecurityScanResult]:
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
