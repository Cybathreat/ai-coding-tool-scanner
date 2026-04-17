#!/usr/bin/env python3
"""
AI Coding Tool Security Scanner
Detects prompt injection vulnerabilities in AI coding tool contexts.
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

# OWASP Top 10 LLM mapping
OWASP_LLM_MAPPINGS = {
    "prompt_injection": "LLM01: Prompt Injection",
    "data_leakage": "LLM02: Sensitive Information Disclosure",
    "symlink_attack": "LLM01: Prompt Injection",
    "schema_exfil": "LLM02: Sensitive Information Disclosure",
}

# NIST AI RMF mapping
NIST_RMF_MAPPINGS = {
    "prompt_injection": "GOVERN 2.1",
    "data_leakage": "PROTECT 2.5",
    "symlink_attack": "PROTECT 2.3",
    "schema_exfil": "PROTECT 2.5",
}

# Detection patterns
PATTERNS = {
    "hidden_html_comment": re.compile(r'<!--\s*(?:HEY\s+(?:COPILOT|CURSOR|CLAUDE)|IGNORE\s+PREVIOUS|EXFILTRATE|READ\s+THE\s+(?:FILE|JSON|SECRET))', re.IGNORECASE),
    "symlink_outside": re.compile(r'^\.\./|\.\./\.\\./'),
    "json_schema_exfil": re.compile(r'\$schema["\']?\s*:\s*["\']https?://(?!json-schema\.org)'),
    "hidden_instruction": re.compile(r'(?:IGNORE\s+(?:ALL\s+)?PREVIOUS|FOLLOW\s+THIS\s+INSTRUCTION|EXECUTE\s+THIS|SYSTEM\s+PROMPT)', re.IGNORECASE),
    "secret_path_reference": re.compile(r'/workspaces/|/home/runner/|/etc/passwd|\.env|secrets\.json|credentials', re.IGNORECASE),
}

class ScanResult:
    def __init__(self, file_path: str, line_number: int, pattern_type: str, match: str, severity: str):
        self.file_path = file_path
        self.line_number = line_number
        self.pattern_type = pattern_type
        self.match = match[:100] + "..." if len(match) > 100 else match
        self.severity = severity
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "type": self.pattern_type,
            "match": self.match,
            "severity": self.severity,
            "owasp": OWASP_LLM_MAPPINGS.get(self.pattern_type, "Unknown"),
            "nist_rmf": NIST_RMF_MAPPINGS.get(self.pattern_type, "Unknown"),
        }

def scan_file(file_path: Path) -> List[ScanResult]:
    """Scan a single file for vulnerabilities."""
    results = []
    
    # Check for symlinks first
    if file_path.is_symlink():
        try:
            target = os.readlink(file_path)
            if target.startswith('../') or '/workspaces/' in target or '/etc/' in target:
                results.append(ScanResult(
                    file_path=str(file_path),
                    line_number=0,
                    pattern_type="symlink_attack",
                    match=f"Symlink -> {target}",
                    severity="HIGH",
                ))
        except:
            pass
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return results
    
    for line_num, line in enumerate(lines, 1):
        for pattern_type, pattern in PATTERNS.items():
            if pattern.search(line):
                severity = "HIGH" if pattern_type in ["hidden_html_comment", "symlink_outside", "secret_path_reference"] else "MEDIUM"
                results.append(ScanResult(
                    file_path=str(file_path),
                    line_number=line_num,
                    pattern_type=pattern_type,
                    match=line.strip(),
                    severity=severity,
                ))
    
    return results

def scan_directory(root_path: Path) -> List[ScanResult]:
    """Recursively scan a directory."""
    all_results = []
    
    # Files to scan
    extensions = ['.md', '.txt', '.json', '.yaml', '.yml', '.py', '.js', '.ts', '.tsx', '.jsx', '.html', '.htm', '.rst', '.adoc']
    
    for ext in extensions:
        for file_path in root_path.rglob(f'*{ext}'):
            if '.git' not in str(file_path) and 'node_modules' not in str(file_path):
                all_results.extend(scan_file(file_path))
    
    # Check all symlinks
    for file_path in root_path.rglob('*'):
        if file_path.is_symlink() and '.git' not in str(file_path):
            try:
                target = os.readlink(file_path)
                if target.startswith('../') or '/workspaces/' in target or '/etc/' in target:
                    all_results.append(ScanResult(
                        file_path=str(file_path),
                        line_number=0,
                        pattern_type="symlink_attack",
                        match=f"Symlink -> {target}",
                        severity="HIGH",
                    ))
            except:
                pass
    
    return all_results

def generate_report(results: List[ScanResult], output_format: str = 'json') -> str:
    """Generate scan report."""
    if output_format == 'json':
        return json.dumps({
            "summary": {
                "total_findings": len(results),
                "high_severity": sum(1 for r in results if r.severity == "HIGH"),
                "medium_severity": sum(1 for r in results if r.severity == "MEDIUM"),
            },
            "findings": [r.to_dict() for r in results],
        }, indent=2)
    else:
        # Human-readable format
        report = f"\n{'='*60}\nAI CODING TOOL SECURITY SCAN REPORT\n{'='*60}\n\n"
        report += f"Total Findings: {len(results)}\n"
        report += f"  HIGH:   {sum(1 for r in results if r.severity == 'HIGH')}\n"
        report += f"  MEDIUM: {sum(1 for r in results if r.severity == 'MEDIUM')}\n\n"
        
        if results:
            report += "-"*60 + "\nFINDINGS:\n" + "-"*60 + "\n\n"
            for r in results:
                report += f"[{r.severity}] {r.pattern_type}\n"
                report += f"  File: {r.file_path}:{r.line_number}\n"
                report += f"  Match: {r.match}\n"
                report += f"  OWASP: {r.to_dict()['owasp']}\n"
                report += f"  NIST AI RMF: {r.to_dict()['nist_rmf']}\n\n"
        else:
            report += "No vulnerabilities detected.\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(description='AI Coding Tool Security Scanner')
    parser.add_argument('--scan', '-s', type=str, help='Directory to scan')
    parser.add_argument('--report', '-r', choices=['json', 'text'], default='text', help='Report format')
    parser.add_argument('--fix', '-f', action='store_true', help='Generate fix suggestions')
    parser.add_argument('--output', '-o', type=str, help='Output file path')
    
    args = parser.parse_args()
    
    if not args.scan:
        args.scan = '.'
    
    root_path = Path(args.scan)
    if not root_path.exists():
        print(f"Error: Directory {args.scan} does not exist")
        return 1
    
    print(f"Scanning {root_path}...")
    results = scan_directory(root_path)
    report = generate_report(results, args.report)
    
    if args.fix and results:
        report += "\n" + "="*60 + "\nREMEDIATION SUGGESTIONS\n" + "="*60 + "\n\n"
        report += """1. HIDDEN HTML COMMENTS: Remove or sanitize HTML comments in markdown/docs
   - Pattern: <!-- ... --> containing instructions to AI tools
   - Fix: Delete comments or use safe documentation practices

2. SYMLINK ATTACKS: Audit and restrict symlinks
   - Pattern: Symlinks pointing outside workspace (/../, /workspaces/, /etc/)
   - Fix: Remove symlinks or configure AI tools to ignore them

3. JSON SCHEMA EXFIL: Block external schema fetching
   - Pattern: $schema pointing to non-json-schema.org domains
   - Fix: Set json.schemaDownload.enable: false in editor config

4. HIDDEN INSTRUCTIONS: Sanitize all input to AI tools
   - Pattern: "Ignore previous instructions", "Execute this"
   - Fix: Implement input validation and prompt hardening

5. SECRET PATH REFERENCES: Never reference secrets in code
   - Pattern: References to .env, credentials, /workspaces/secrets
   - Fix: Use environment variables, never commit secrets

OWASP Top 10 LLM Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
NIST AI RMF Reference: https://www.nist.gov/itl/ai-risk-management-framework
"""
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)
    
    return 0 if not results else 1

if __name__ == '__main__':
    exit(main())
