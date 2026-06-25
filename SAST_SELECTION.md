# SAST Vulnerability Selection - InsecureWebApp

Project: https://github.com/kadraman/InsecureWebApp
Local path: `/home/carlos/DSS/InsecureWebApp`

Initial scan evidence:

- Bandit: `/home/carlos/DSS/insecurewebapp-bandit-before.json`
- Semgrep: `/home/carlos/DSS/insecurewebapp-semgrep-before.json`

## Recommended 3 vulnerabilities

These three are interesting, technically strong, and appear in both Bandit and Semgrep.

| # | Vulnerability | Files / lines | Bandit finding | Semgrep finding |
|---|---|---|---|---|
| 1 | Command Injection | `iwa/blueprints/insecure/insecure_routes.py:86` | `B605` | `dangerous-system-call` |
| 2 | Insecure Deserialization with pickle | `iwa/blueprints/auth/auth_routes.py:89` | `B301` / `B403` | `avoid-pickle` |
| 3 | SQL Injection | `iwa/blueprints/products/products_api_routes.py:37`; `iwa/blueprints/products/repository.py:39,115` | `B608` | `tainted-sql-string` / `sqlalchemy-execute-raw-query` |

---

## 1. Command Injection

### Vulnerable code

File: `iwa/blueprints/insecure/insecure_routes.py`

```python
arguments = request.args.get('arguments')
home = os.getenv('APPHOME')
cmd = home.join(INITCMD).join(arguments)
os.system(cmd)
```

### Problem

User-controlled input is used to build an operating system command and execute it through `os.system()`. This can allow an attacker to inject additional shell commands.

### Recommended correction

Avoid shell execution and avoid concatenating user input into a command string. Use `subprocess.run()` with a fixed command allowlist and argument list.

Example remediation:

```python
import subprocess
from flask import abort

ALLOWED_COMMANDS = {
    "status": ["/usr/bin/uptime"],
    "disk": ["/usr/bin/df", "-h"],
}

@insecure_bp.route("/command_injection", methods=["GET"])
def command_injection():
    action = request.args.get("action", "status")
    command = ALLOWED_COMMANDS.get(action)
    if command is None:
        abort(400, "Unsupported command")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        timeout=5,
    )
    return result.stdout, 200, {"Content-Type": "text/plain"}
```

### Report wording

The original implementation used `os.system()` with user-controlled input, creating a command injection risk. The remediation replaced shell command construction with `subprocess.run()` using `shell=False`, a fixed allowlist of supported actions, and a timeout. This prevents arbitrary command execution while preserving the intended functionality.

---

## 2. Insecure Deserialization with pickle

### Vulnerable code

File: `iwa/blueprints/auth/auth_routes.py`

```python
b64 = request.cookies.get('rememberme')
a = pickle.loads(base64.b64decode(b64))
session["email"] = a.email
```

### Problem

`pickle.loads()` can execute code during deserialization if an attacker controls the serialized payload. Since the value comes from a client-side cookie, this is a high-risk insecure deserialization vulnerability.

### Recommended correction

Do not deserialize untrusted data with pickle. Use Flask signed sessions or a signed JSON token with `itsdangerous`.

Example remediation using `itsdangerous`:

```python
from itsdangerous import URLSafeSerializer, BadSignature
from flask import current_app

serializer = URLSafeSerializer(current_app.config["SECRET_KEY"], salt="rememberme")

if "rememberme" in request.cookies:
    token = request.cookies.get("rememberme")
    try:
        data = serializer.loads(token)
    except BadSignature:
        abort(400, "Invalid remember-me token")

    session.clear()
    session["email"] = data["email"]
    session["loggedin"] = True
    return redirect(url_for("users.home"))
```

### Report wording

The application deserialized a client-controlled cookie using Python pickle. Because pickle can execute arbitrary code during object reconstruction, this represents insecure deserialization. The remediation replaced pickle with signed structured data, ensuring the token can be verified and parsed without executing attacker-controlled code.

---

## 3. SQL Injection

### Vulnerable code

Files:

- `iwa/blueprints/products/products_api_routes.py`
- `iwa/blueprints/products/repository.py`

Example:

```python
keywords = request.args.get('keywords', '')
query = "SELECT * FROM products WHERE name LIKE '%" + keywords + "%'"
products = db.execute(query).fetchall()
```

### Problem

User-controlled input is concatenated directly into SQL statements. An attacker can alter the SQL query structure and access or modify data.

### Recommended correction

Use parameterized queries.

Example remediation:

```python
keywords = request.args.get("keywords", "")
pattern = f"%{keywords}%"
products = db.execute(
    "SELECT * FROM products WHERE name LIKE ?",
    (pattern,),
).fetchall()
```

For repository methods:

```python
data = (
    get_db()
    .execute(
        "SELECT * FROM products p WHERE name LIKE ? ORDER BY name",
        (f"%{keywords}%",),
    )
    .fetchall()
)
```

```python
data = (
    get_db()
    .execute(
        "SELECT * FROM reviews r WHERE content LIKE ? ORDER BY date DESC",
        (f"%{keywords}%",),
    )
    .fetchall()
)
```

### Report wording

The original code built SQL queries by concatenating user input directly into the query string. This allows SQL injection because input can change the intended query syntax. The remediation introduced parameterized queries, where user input is passed separately as data. This prevents the database from interpreting user input as SQL code.

---

## After remediation scan commands

Run these after applying the fixes:

```bash
cd /home/carlos/DSS/InsecureWebApp
bandit -r . -f json -o ../insecurewebapp-bandit-after.json
semgrep scan --config auto --json -o ../insecurewebapp-semgrep-after.json
cd /home/carlos/DSS
python -m json.tool insecurewebapp-bandit-after.json > tmp && mv tmp insecurewebapp-bandit-after.json
python -m json.tool insecurewebapp-semgrep-after.json > tmp && mv tmp insecurewebapp-semgrep-after.json
```

## Report structure

1. Project and technology selection
2. SAST tools used: Bandit and Semgrep
3. Initial scan results
4. Selected vulnerabilities
5. Code-level analysis and remediation
6. Final scan results and comparison
7. Short conclusion
