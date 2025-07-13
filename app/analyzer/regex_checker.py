import re

# Sample rules – you can load these from rules.yaml later

regex_rules = [
    {
        "pattern": r'\beval\s*\(',
        "message": "⚠️ Avoid using `eval()`. It can lead to remote code execution.",
    },
    {
        "pattern": r'\bexec\s*\(',
        "message": "⚠️ Avoid using `exec()`. It can lead to remote code execution.",
    },
    {
        "pattern": r'\bos\.system\s*\(',
        "message": "⚠️ Avoid using `os.system()`. It can lead to command injection vulnerabilities.",
    },
    {
        "pattern": r'\bsubprocess\.Popen\s*\(',
        "message": "⚠️ Avoid using `subprocess.Popen()`. It can lead to command injection vulnerabilities.",
    },
    {
        "pattern": r'password\s*=\s*[\'"].+[\'"]',
        "message": "🔐 Hardcoded password found. Consider using environment variables or a secure vault.",
    },
    {
        "pattern": r'\b[A-Za-z0-9_-]{20,}\b',
        "message": "🔐 Hardcoded API key or sensitive token detected. Avoid storing sensitive information in code.",
    },
    {
        "pattern": r'\bhashlib\.(md5|sha1)\s*\(',
        "message": "⚠️ Insecure hashing algorithm detected. Use a stronger algorithm like `bcrypt`.",
    },
    {
        "pattern": r'\byaml\.load\s*\(',
        "message": "⚠️ Unsafe YAML loading detected. Use `yaml.safe_load()` or specify a safe loader.",
    },
    {
        "pattern": r'(?i)(select|update|delete|insert|SELECT|UPDATE|DELETE|INSERT)\s.+\s\+\s.*',
        "message": "⚠️ Possible raw SQL query detected. Use parameterized queries to prevent SQL injection.",
    },
       {
        "pattern": r'\?.*session_id=',
        "message": "⚠️ Session parameters should not be passed in URLs.",
    },
    {
        "pattern": r'set_cookie\(.+secure=False',
        "message": "⚠️ Cookies should be marked as secure to ensure they are transmitted over HTTPS.",
    },
    {
        "pattern": r'\bCrypto\.Cipher\.DES\b',
        "message": "⚠️ Insecure cryptographic algorithm detected. Use AES or other modern algorithms.",
    },
    {
        "pattern": r'http://.*',
        "message": "⚠️ Sensitive data should not be transmitted over HTTP. Use HTTPS instead.",
    },
    {
        "pattern": r'log\.(info|debug|error)\(.*password.*\)',
        "message": "⚠️ Sensitive information (e.g., passwords) should not be logged.",
    },
    {
        "pattern": r'traceback\.format_exc\(',
        "message": "⚠️ Stack traces should not be exposed to users.",
    }
]



def run_regex_checks(code: str, filename: str) -> list:
    """
    Runs all regex rules against a string of code.
    Returns list of issues with line number (position).
    """
    issues = []
    lines = code.split("\n")

    for i, line in enumerate(lines, start=1):
        for rule in regex_rules:
            if re.search(rule["pattern"], line):
                issues.append({
                    "filename": filename,
                    "line": i,
                    "position": i,  # For now assume diff position = line number
                    "message": rule["message"],
                    "snippet": line.strip()
                })

    return issues
