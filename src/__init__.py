"""AI Coding Tool Security Scanner.

Detects prompt injection vulnerabilities in AI coding tool contexts.
Maps findings to OWASP Top 10 for LLM Applications and NIST AI RMF.
"""

__version__ = "1.0.0"
__author__ = "Cybathreat"
__email__ = "ahmed.chiboub@cybacrest.com"

from .scanner import scan_file, scan_directory, generate_report, ScanResult

__all__ = ["scan_file", "scan_directory", "generate_report", "ScanResult"]
