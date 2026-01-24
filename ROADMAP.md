# Tool-Scan Roadmap: Becoming the Industry Standard for MCP Security

## Vision
Transform Tool-Scan from a static security scanner into the **definitive MCP security platform** — the npm audit/Snyk equivalent for the AI agent ecosystem.

---

## Phase 1: Foundation (Current - v1.x)
*Status: ✅ Complete*

### Core Capabilities
- [x] MCP 2025-11-25 specification compliance validation
- [x] Security threat detection (prompt injection, tool poisoning, command injection, SQL injection, XSS, SSRF)
- [x] JSON Schema validation (Draft-07 & 2020-12)
- [x] Unified 1-100 scoring with letter grades
- [x] CLI with JSON output for CI/CD
- [x] 147 tests

---

## Phase 2: OWASP MCP Top 10 Coverage (v2.0)
*Target: Q1 2026*

Align with the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) security risks:

### New Detections
- [ ] **MCP01: Tool Poisoning** - Enhanced detection for:
  - Rug pull attacks (malicious updates to trusted tools)
  - Schema poisoning (corrupted interface definitions)
  - Tool shadowing (fake/duplicate tools)
- [ ] **MCP02: Excessive Agency** - Tools with overly broad permissions
- [ ] **MCP03: Context Manipulation** - Memory/state poisoning attempts
- [ ] **MCP04: Insecure Tool Binding** - Weak tool-to-server associations
- [ ] **MCP05: Credential Exposure** - Token passthrough anti-patterns
- [ ] **MCP06: Prompt Injection via Context** - Indirect injection in tool responses
- [ ] **MCP07: Cross-Origin Escalation** - Tools accessing unauthorized resources
- [ ] **MCP08: Insufficient Output Sanitization** - Unescaped response data
- [ ] **MCP09: Resource Exhaustion** - DoS via tool abuse
- [ ] **MCP10: Audit Log Gaps** - Missing observability hooks

### Deliverables
- [ ] OWASP compliance report generation
- [ ] Severity mapping to OWASP categories
- [ ] Remediation guidance per OWASP item

---

## Phase 3: Behavioral Analysis (v2.5)
*Target: Q2 2026*

Move beyond static analysis to **intent vs. behavior verification** (inspired by [Cisco's MCP Scanner](https://blogs.cisco.com/ai/ciscos-mcp-scanner-introduces-behavioral-code-threat-analysis)):

### Features
- [ ] **Semantic Analysis** - Compare tool descriptions to actual capabilities
- [ ] **Intent Mismatch Detection** - Flag when behavior doesn't match documentation
- [ ] **Capability Mapping** - Auto-detect what a tool can actually do vs. claims
- [ ] **Least Privilege Scoring** - Rate tools on permission minimization

### Technical Implementation
- [ ] AST analysis for code-level inspection
- [ ] LLM-assisted semantic comparison
- [ ] Capability fingerprinting

---

## Phase 4: Runtime Monitoring (v3.0)
*Target: Q3 2026*

Add **proxy-based runtime protection** (similar to [MCP-Scan's proxy mode](https://github.com/invariantlabs-ai/mcp-scan)):

### Features
- [ ] **MCP Proxy Server** - Intercept and analyze live traffic
- [ ] **Real-time Guardrails** - Block suspicious tool invocations
- [ ] **Behavioral Baselines** - Learn normal patterns, detect anomalies
- [ ] **Session Recording** - Audit trail of all tool interactions
- [ ] **Alert System** - Webhooks, Slack, PagerDuty integrations

### Anomaly Detection
- [ ] Unusual request patterns
- [ ] Privilege escalation attempts
- [ ] Data exfiltration indicators
- [ ] Agent looping/excessive chaining

---

## Phase 5: Enterprise & Compliance (v3.5)
*Target: Q4 2026*

Make Tool-Scan **enterprise-ready** for SOC 2, ISO 27001, and regulated industries:

### Governance Features
- [ ] **Tool Registry Integration** - Approved/denied tool lists
- [ ] **Policy Engine** - Custom security rules (YAML/JSON)
- [ ] **Namespace Management** - Organization-scoped tool approval
- [ ] **Cryptographic Verification** - Signature validation for tools
- [ ] **Version Pinning** - Lock tool versions, detect drift

### Compliance Reporting
- [ ] SOC 2 evidence generation
- [ ] ISO 27001 control mapping
- [ ] NIST AI RMF alignment
- [ ] Custom compliance frameworks

### Enterprise Integrations
- [ ] SIEM integration (Splunk, Elastic, Datadog)
- [ ] SOAR playbook triggers
- [ ] ServiceNow/Jira ticket creation
- [ ] SSO/SAML for dashboard access

---

## Phase 6: Registry & Certification (v4.0)
*Target: 2027*

Become the **trust authority** for the MCP ecosystem:

### Tool-Scan Verified Program
- [ ] **Certification Badges** - Verified secure tools
- [ ] **Public Registry** - Searchable database of scanned tools
- [ ] **Continuous Monitoring** - Re-scan on updates
- [ ] **Vulnerability Database** - CVE-style tracking for MCP threats

### Registry Features
- [ ] API for registry queries
- [ ] Webhook notifications for tool updates
- [ ] Dependency scanning (tool chains)
- [ ] Supply chain attestation (SLSA)

### Community
- [ ] Open vulnerability submission
- [ ] Bug bounty integration
- [ ] Threat intelligence sharing

---

## Technical Milestones

### Performance
- [ ] Scan 1000+ tools in <10 seconds
- [ ] Incremental scanning (only changed tools)
- [ ] Distributed scanning for large deployments

### Integrations
- [ ] **IDE Plugins** - VS Code, JetBrains, Cursor
- [ ] **CI/CD** - GitHub Actions, GitLab CI, Jenkins
- [ ] **Package Managers** - pip, npm, cargo pre-install hooks
- [ ] **Container Scanning** - Docker image analysis
- [ ] **Cloud Native** - Kubernetes admission controller

### API & SDK
- [ ] REST API for programmatic access
- [ ] Python SDK
- [ ] JavaScript/TypeScript SDK
- [ ] Go SDK

---

## Competitive Positioning

| Feature | Tool-Scan | MCP-Scan | Enkrypt AI | MCPScan.ai |
|---------|-----------|----------|------------|------------|
| Open Source | ✅ | ✅ | ❌ | ❌ |
| OWASP MCP Top 10 | 🚧 v2.0 | Partial | Unknown | Unknown |
| Runtime Proxy | 🚧 v3.0 | ✅ | ❌ | ❌ |
| Enterprise Compliance | 🚧 v3.5 | ❌ | ✅ | ✅ |
| Tool Registry | 🚧 v4.0 | ❌ | ❌ | ❌ |
| Certification Program | 🚧 v4.0 | ❌ | ❌ | ❌ |

---

## Success Metrics

### Adoption
- [ ] 10,000 GitHub stars
- [ ] 100,000 monthly PyPI downloads
- [ ] 50+ enterprise deployments
- [ ] Integration with 3+ major AI platforms

### Community
- [ ] 100+ contributors
- [ ] Active Discord/Slack community
- [ ] Regular security advisories
- [ ] Conference presentations (DEF CON, Black Hat, OWASP)

### Industry Recognition
- [ ] Referenced in OWASP guidelines
- [ ] Cited in academic papers
- [ ] Endorsed by major cloud providers
- [ ] Default scanner for MCP registries

---

## References

### OWASP & Standards
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP MCP Security Cheatsheet](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/)
- [OWASP Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)

### Industry Analysis
- [Red Hat: MCP Security Risks](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)
- [Microsoft: Protecting Against Indirect Prompt Injection in MCP](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp)
- [Cisco: Behavioral Code Threat Analysis](https://blogs.cisco.com/ai/ciscos-mcp-scanner-introduces-behavioral-code-threat-analysis)
- [Practical DevSecOps: MCP Vulnerabilities 2026](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)

### Tools & Ecosystem
- [MCP-Scan by Invariant Labs](https://github.com/invariantlabs-ai/mcp-scan)
- [Official MCP Registry](https://registry.modelcontextprotocol.io/)
- [Docker MCP Catalog](https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/)
- [ToolHive Verification](https://dev.to/stacklok/from-unknown-to-verified-solving-the-mcp-server-trust-problem-5967)

### Research
- [Enterprise-Grade Security for MCP (arXiv)](https://arxiv.org/pdf/2504.08623)
- [Securing AI Agent Execution (arXiv)](https://arxiv.org/html/2510.21236)
- [Red Canary: MCP Threat Landscape](https://redcanary.com/blog/threat-detection/mcp-ai-workflows/)

---

*This roadmap is a living document. Contributions and feedback welcome!*

*Last updated: January 24, 2026*
