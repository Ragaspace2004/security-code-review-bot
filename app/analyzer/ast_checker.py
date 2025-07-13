import ast

# List of known dangerous function calls
DANGEROUS_FUNCTIONS = ["eval", "exec", "compile", "open", "os.system", "subprocess.Popen"]

def run_ast_checks(code: str, filename: str) -> list:
    issues = []

    if not code:
        return issues  # No code to analyze

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        print(f"⚠️ Syntax error in {filename}: {e}")
        return []

    for node in ast.walk(tree):
        # 🕵️ Check for function calls
        if isinstance(node, ast.Call):
            func_name = get_func_name(node)

            if func_name in DANGEROUS_FUNCTIONS:
                issues.append({
                    "filename": filename,
                    "line": node.lineno,
                    "position": node.lineno,
                    "message": f"⚠️ Dangerous function `{func_name}()` used. Avoid unless absolutely needed."
                })

            # 🔐 Check for unsafe YAML loading
            if func_name == "yaml.load":
                if not any(arg for arg in node.keywords if arg.arg == "Loader"):
                    issues.append({
                        "filename": filename,
                        "line": node.lineno,
                        "position": node.lineno,
                        "message": "⚠️ Unsafe YAML loading detected. Use `yaml.safe_load()` or specify a safe loader."
                    })

            # 🔒 Check for insecure hashing algorithms
            if func_name in ["hashlib.md5", "hashlib.sha1"]:
                issues.append({
                    "filename": filename,
                    "line": node.lineno,
                    "position": node.lineno,
                    "message": f"⚠️ Insecure hashing algorithm `{func_name}` used. Use a stronger algorithm like `bcrypt`."
                })

        # 🔐 Check for hardcoded passwords
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and "pass" in target.id.lower():
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        issues.append({
                            "filename": filename,
                            "line": node.lineno,
                            "position": node.lineno,
                            "message": "🔐 Hardcoded password detected in variable assignment."
                        })

                # 🔑 Check for hardcoded sensitive information
                if isinstance(target, ast.Name) and any(keyword in target.id.lower() for keyword in ["key", "token", "secret"]):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        issues.append({
                            "filename": filename,
                            "line": node.lineno,
                            "position": node.lineno,
                            "message": "🔐 Hardcoded sensitive information detected. Avoid storing API keys in code."
                        })
        if isinstance(node, ast.FunctionDef):
            if not any(isinstance(subnode, ast.Try) for subnode in ast.walk(node)):
                issues.append({
            "filename": filename,
            "line": node.lineno,
            "position": node.lineno,
            "message": "⚠️ Missing exception handling in this function."
             })
            
        if isinstance(node, ast.Call) and get_func_name(node) == "set_cookie":
            if not any(kw.arg == "max_age" for kw in node.keywords):
                issues.append({
            "filename": filename,
            "line": node.lineno,
            "position": node.lineno,
            "message": "⚠️ Session cookies should have an expiry time."
             })
        if isinstance(node, ast.Call) and get_func_name(node) == "check_permission":
            if not any(arg for arg in node.args if isinstance(arg, ast.Str)):
                issues.append({
            "filename": filename,
            "line": node.lineno,
            "position": node.lineno,
            "message": "⚠️ Granular authorization checks (e.g., roles) are missing."
        })

        # ⚠️ Check for SQL queries with string interpolation
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.BinOp) or isinstance(node.value, ast.JoinedStr):
                if "SELECT" in ast.dump(node.value) or "INSERT" in ast.dump(node.value):
                    issues.append({
                        "filename": filename,
                        "line": node.lineno,
                        "position": node.lineno,
                        "message": "⚠️ SQL query with string interpolation detected. Use parameterized queries instead."
                    })

    return issues


def get_func_name(node):
    """
    Returns full function name from AST Call node.
    Handles both simple and attribute calls (e.g., os.system).
    """
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        # Recursively build dotted name like os.system
        return get_full_attr_name(node.func)
    return ""


def get_full_attr_name(attr_node):
    """
    Recursively builds the full attribute name (e.g., os.system).
    """
    if isinstance(attr_node, ast.Attribute):
        return f"{get_full_attr_name(attr_node.value)}.{attr_node.attr}"
    elif isinstance(attr_node, ast.Name):
        return attr_node.id
    return ""




