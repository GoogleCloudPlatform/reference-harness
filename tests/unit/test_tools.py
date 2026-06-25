# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for security scanning tool wrappers."""

# Disabling import-outside-toplevel because test mocks defer module loading
# pylint: disable=import-outside-toplevel

from pathlib import Path

from app.tools import find_references


def test_find_references_invalid_symbols():
    # Symbols must be valid python/C identifiers
    invalid_symbols = ["", "123foo", "foo-bar", "foo bar", "foo.bar", "eval()"]
    for symbol in invalid_symbols:
        res = find_references(symbol, "/tmp")
        assert res["status"] == "error"
        assert "invalid symbol name" in res["error"]


def test_find_references_valid_symbols(tmp_path: Path):
    # Create temporary files with some code
    file_a = tmp_path / "service.py"
    file_b = tmp_path / "handler.js"
    file_c = tmp_path / "other.txt"

    file_a.write_text(
        "def handle_request(request):\n"
        "    data = request.get_json()\n"
        "    process_data(data)\n"
    )
    file_b.write_text(
        "function process_data(payload) {\n    console.log(payload);\n}\n"
    )
    file_c.write_text("This is standard text with process_data symbol.\n")

    # Search for process_data
    res = find_references("process_data", str(tmp_path))
    assert res["status"] == "success"
    assert res["count"] >= 2

    files_matched = {match["file"] for match in res["matches"]}
    assert str(file_a) in files_matched
    assert str(file_b) in files_matched

    # Test extension filter
    res_py = find_references(
        "process_data", str(tmp_path), file_extensions=["py"]
    )
    assert res_py["status"] == "success"
    assert res_py["count"] == 1
    assert res_py["matches"][0]["file"] == str(file_a)


def test_find_references_whole_word_only(tmp_path: Path):
    file_a = tmp_path / "code.py"
    file_a.write_text(
        "variable_name = 1\n"
        "variable_name_suffix = 2\n"
        "prefix_variable_name = 3\n"
        "print(variable_name)\n"
    )

    res = find_references("variable_name", str(tmp_path))
    assert res["status"] == "success"
    # It should match variable_name on line 1 and line 4, but NOT line 2 or 3
    assert res["count"] == 2
    lines = {match["line"] for match in res["matches"]}
    assert 1 in lines
    assert 4 in lines
    assert 2 not in lines
    assert 3 not in lines


def test_run_semgrep_sarif_normalization():
    from unittest.mock import patch

    from app.tools import run_semgrep

    mock_semgrep_stdout = """{
        "results": [
            {
                "check_id": "rules.eval-injection",
                "path": "app.py",
                "start": {"line": 8},
                "extra": {
                    "severity": "ERROR",
                    "message": "Unsafe eval usage",
                    "lines": "eval(request.args.get('expr'))",
                    "metadata": {
                        "cwe": ["CWE-94"]
                    }
                }
            }
        ]
    }"""
    with patch("app.tools._exec_scanner") as mock_exec:
        mock_exec.return_value = {
            "status": "ran",
            "stdout": mock_semgrep_stdout,
            "stderr": "",
            "returncode": 0,
        }
        res = run_semgrep("/dummy/path")
        assert res["status"] == "success"
        assert res["count"] == 1
        finding = res["findings"][0]
        assert finding["ruleId"] == "rules.eval-injection"
        assert finding["level"] == "error"
        assert finding["message"]["text"] == "Unsafe eval usage"
        assert (
            finding["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ]
            == "app.py"
        )
        assert (
            finding["locations"][0]["physicalLocation"]["region"]["startLine"]
            == 8
        )
        assert finding["properties"]["scanner"] == "semgrep"
        assert finding["properties"]["cwe"] == ["CWE-94"]
        assert (
            finding["properties"]["evidence"]
            == "eval(request.args.get('expr'))"
        )


def test_run_trivy_sarif_normalization():
    from unittest.mock import patch

    from app.tools import run_trivy

    mock_trivy_stdout = """{
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-34012",
                        "Severity": "HIGH",
                        "Title": "Prototype pollution in lodash",
                        "CweIDs": ["CWE-1321"],
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.20",
                        "FixedVersion": "4.17.21"
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "generic-aws-key",
                        "Severity": "CRITICAL",
                        "StartLine": 12,
                        "Title": "AWS access key leaked",
                        "Match": "AWS_KEY=AKIA..."
                    }
                ]
            }
        ]
    }"""
    with patch("app.tools._exec_scanner") as mock_exec:
        mock_exec.return_value = {
            "status": "ran",
            "stdout": mock_trivy_stdout,
            "stderr": "",
            "returncode": 0,
        }
        res = run_trivy("/dummy/path")
        assert res["status"] == "success"
        assert res["count"] == 2

        # Check vuln first (stable sort order)
        vuln = res["findings"][0]
        assert vuln["ruleId"] == "trivy.vuln.CVE-2023-34012"
        assert vuln["level"] == "error"
        assert vuln["properties"]["package"] == "lodash"
        assert vuln["properties"]["installed_version"] == "4.17.20"
        assert vuln["properties"]["fixed_version"] == "4.17.21"

        # Check secret second
        secret = res["findings"][1]
        assert secret["ruleId"] == "trivy.secret.generic-aws-key"
        assert secret["level"] == "error"
        assert (
            secret["locations"][0]["physicalLocation"]["region"]["startLine"]
            == 12
        )
        assert secret["properties"]["scanner"] == "trivy"
        assert secret["properties"]["evidence"] == "AWS_KEY=AKIA..."


def test_run_gitleaks_sarif_normalization():
    from unittest.mock import patch

    from app.tools import run_gitleaks

    mock_gitleaks_stdout = """[
        {
            "Description": "AWS Access Key ID",
            "StartLine": 15,
            "File": "aws_config.py",
            "RuleID": "aws-access-key",
            "Match": "AWS_SECRET=AKIA12345"
        }
    ]"""
    with patch("app.tools._exec_scanner") as mock_exec:
        mock_exec.return_value = {
            "status": "ran",
            "stdout": mock_gitleaks_stdout,
            "stderr": "",
            "returncode": 1,
        }
        res = run_gitleaks("/dummy/path")
        assert res["status"] == "success"
        assert res["count"] == 1
        finding = res["findings"][0]
        assert finding["ruleId"] == "gitleaks.secret.aws-access-key"
        assert finding["level"] == "error"
        assert (
            finding["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ]
            == "aws_config.py"
        )
        assert (
            finding["locations"][0]["physicalLocation"]["region"]["startLine"]
            == 15
        )
        assert finding["properties"]["scanner"] == "gitleaks"
        assert finding["properties"]["cwe"] == ["CWE-798"]
        assert finding["properties"]["evidence"] == "AWS_SECRET=AKIA12345"


def test_run_bandit_sarif_normalization():
    from unittest.mock import patch

    from app.tools import run_bandit

    mock_bandit_stdout = """{
        "results": [
            {
                "test_id": "B102",
                "filename": "calculator.py",
                "issue_severity": "HIGH",
                "issue_text": "Use of possibly insecure function eval()",
                "line_number": 24,
                "code": "eval(user_input)",
                "issue_cwe": {"id": 95}
            }
        ]
    }"""
    with patch("app.tools._exec_scanner") as mock_exec:
        mock_exec.return_value = {
            "status": "ran",
            "stdout": mock_bandit_stdout,
            "stderr": "",
            "returncode": 0,
        }
        res = run_bandit("/dummy/path")
        assert res["status"] == "success"
        assert res["count"] == 1
        finding = res["findings"][0]
        assert finding["ruleId"] == "bandit.sast.B102"
        assert finding["level"] == "error"
        assert (
            finding["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ]
            == "calculator.py"
        )
        assert (
            finding["locations"][0]["physicalLocation"]["region"]["startLine"]
            == 24
        )
        assert finding["properties"]["scanner"] == "bandit"
        assert finding["properties"]["cwe"] == ["CWE-95"]
        assert finding["properties"]["evidence"] == "eval(user_input)"


def test_query_ast_python(tmp_path: Path):
    from app.tools import query_ast

    file_py = tmp_path / "target.py"
    file_py.write_text("def process_data(data):\n    return eval(data)\n")

    query = """
    (function_definition
      name: (identifier) @name)
    """
    res = query_ast(str(file_py), query, "python")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "process_data"
    assert res["matches"][0]["line"] == 1
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_javascript(tmp_path: Path):
    from app.tools import query_ast

    file_js = tmp_path / "target.js"
    file_js.write_text(
        "const secret_key = 'supersecret';\nconsole.log(secret_key);\n"
    )

    query = """
    (lexical_declaration
      (variable_declarator
        name: (identifier) @var_name
        value: (string) @val))
    """
    res = query_ast(str(file_js), query, "javascript")
    assert res["status"] == "success"
    assert res["count"] == 2
    captures = {m["capture"]: m["snippet"] for m in res["matches"]}
    assert captures["var_name"] == "secret_key"
    assert captures["val"] == "'supersecret'"
    assert res["matches"][0]["line"] == 1


def test_query_ast_invalid_query(tmp_path: Path):
    from app.tools import query_ast

    file_py = tmp_path / "target.py"
    file_py.write_text("print('hello')\n")

    res = query_ast(str(file_py), "(invalid_node_syntax", "python")
    assert res["status"] == "error"
    assert "invalid tree-sitter query" in res["error"]


def test_query_ast_unsupported_language(tmp_path: Path):
    from app.tools import query_ast

    file_txt = tmp_path / "target.txt"
    file_txt.write_text("hello\n")

    res = query_ast(str(file_txt), "(node)", "cobol")
    assert res["status"] == "error"
    assert "unsupported language" in res["error"]


def test_query_ast_java(tmp_path: Path):
    from app.tools import query_ast

    file_java = tmp_path / "Target.java"
    file_java.write_text(
        "class Target {\n"
        "    void processData(String data) {\n"
        "        System.out.println(data);\n"
        "    }\n"
        "}\n"
    )

    query = """
    (method_declaration
      name: (identifier) @name)
    """
    res = query_ast(str(file_java), query, "java")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "processData"
    assert res["matches"][0]["line"] == 2
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_go(tmp_path: Path):
    from app.tools import query_ast

    file_go = tmp_path / "target.go"
    file_go.write_text(
        "package main\n"
        'import "fmt"\n'
        "func processData(data string) {\n"
        "    fmt.Println(data)\n"
        "}\n"
    )

    query = """
    (function_declaration
      name: (identifier) @name)
    """
    res = query_ast(str(file_go), query, "go")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "processData"
    assert res["matches"][0]["line"] == 3
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_c(tmp_path: Path):
    from app.tools import query_ast

    file_c = tmp_path / "target.c"
    file_c.write_text(
        "void processData(char* data) {\n" '    printf("%s\\n", data);\n' "}\n"
    )

    query = """
    (function_definition
      declarator: (function_declarator
        declarator: (identifier) @name))
    """
    res = query_ast(str(file_c), query, "c")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "processData"
    assert res["matches"][0]["line"] == 1
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_cpp(tmp_path: Path):
    from app.tools import query_ast

    file_cpp = tmp_path / "target.cpp"
    file_cpp.write_text(
        "class Target {\n"
        "public:\n"
        "    void processData(int data) {}\n"
        "};\n"
    )

    query = """
    (class_specifier
      name: (type_identifier) @class_name)
    """
    res = query_ast(str(file_cpp), query, "cpp")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "Target"
    assert res["matches"][0]["line"] == 1
    assert res["matches"][0]["capture"] == "class_name"


def test_query_ast_rust(tmp_path: Path):
    from app.tools import query_ast

    file_rust = tmp_path / "target.rs"
    file_rust.write_text(
        "fn process_data(data: String) {\n" '    println!("{}", data);\n' "}\n"
    )

    query = """
    (function_item
      name: (identifier) @name)
    """
    res = query_ast(str(file_rust), query, "rust")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "process_data"
    assert res["matches"][0]["line"] == 1
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_ruby(tmp_path: Path):
    from app.tools import query_ast

    file_ruby = tmp_path / "target.rb"
    file_ruby.write_text("def process_data(data)\n" "  puts data\n" "end\n")

    query = """
    (method
      name: (identifier) @name)
    """
    res = query_ast(str(file_ruby), query, "ruby")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "process_data"
    assert res["matches"][0]["line"] == 1
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_php(tmp_path: Path):
    from app.tools import query_ast

    file_php = tmp_path / "target.php"
    file_php.write_text(
        "<?php\n" "function processData($data) {\n" "    echo $data;\n" "}\n"
    )

    query = """
    (function_definition
      name: (name) @name)
    """
    res = query_ast(str(file_php), query, "php")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "processData"
    assert res["matches"][0]["line"] == 2
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_csharp(tmp_path: Path):
    from app.tools import query_ast

    file_cs = tmp_path / "target.cs"
    file_cs.write_text(
        "class Target {\n"
        "    void ProcessData(string data) {\n"
        "    }\n"
        "}\n"
    )

    query = """
    (method_declaration
      name: (identifier) @name)
    """
    res = query_ast(str(file_cs), query, "csharp")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "ProcessData"
    assert res["matches"][0]["line"] == 2
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_typescript(tmp_path: Path):
    from app.tools import query_ast

    file_ts = tmp_path / "target.ts"
    file_ts.write_text("function processData(data: string): void {\n" "}\n")

    query = """
    (function_declaration
      name: (identifier) @name)
    """
    res = query_ast(str(file_ts), query, "typescript")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "processData"
    assert res["matches"][0]["line"] == 1
    assert res["matches"][0]["capture"] == "name"


def test_query_ast_html(tmp_path: Path):
    from app.tools import query_ast

    file_html = tmp_path / "target.html"
    file_html.write_text('<div id="target">Hello</div>\n')

    query = """
    (element
      (start_tag
        (tag_name) @tag))
    """
    res = query_ast(str(file_html), query, "html")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "div"
    assert res["matches"][0]["line"] == 1
    assert res["matches"][0]["capture"] == "tag"


def test_query_ast_css(tmp_path: Path):
    from app.tools import query_ast

    file_css = tmp_path / "target.css"
    file_css.write_text(".target {\n" "    color: red;\n" "}\n")

    query = """
    (class_selector
      (class_name) @class_name)
    """
    res = query_ast(str(file_css), query, "css")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == "target"
    assert res["matches"][0]["line"] == 1
    assert res["matches"][0]["capture"] == "class_name"


def test_query_ast_json(tmp_path: Path):
    from app.tools import query_ast

    file_json = tmp_path / "target.json"
    file_json.write_text("{\n" '    "key": "value"\n' "}\n")

    query = """
    (pair
      key: (string) @key)
    """
    res = query_ast(str(file_json), query, "json")
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["matches"][0]["snippet"] == '"key"'
    assert res["matches"][0]["line"] == 2
    assert res["matches"][0]["capture"] == "key"


def test_execute_in_sandbox_static_mode():
    import os

    from app.sandbox import execute_in_sandbox

    # Mock configured static mode
    os.environ["VULNCATCHER_SANDBOX_MODE"] = "static"
    try:
        res = execute_in_sandbox("code", "payload", "javascript")
        assert res["status"] == "skipped"
        assert "static-only" in res["reason"]
        assert res["mode_used"] == "static"
    finally:
        del os.environ["VULNCATCHER_SANDBOX_MODE"]


def test_execute_in_sandbox_local_python():
    import os

    from app.sandbox import execute_in_sandbox

    # Mock local host execution mode to verify python execution safely
    os.environ["VULNCATCHER_SANDBOX_MODE"] = "local"
    try:
        code = "def check():\n    return 'active'\n"
        payload = (
            "import target\nprint('Payload verified: ' + target.check())\n"
        )
        res = execute_in_sandbox(code, payload, "python")

        assert res["status"] == "success"
        assert res["exit_code"] == 0
        assert "Payload verified: active" in res["stdout"].strip()
        assert res["mode_used"] == "local"
    finally:
        del os.environ["VULNCATCHER_SANDBOX_MODE"]


def test_execute_in_sandbox_local_bash():
    import os

    from app.sandbox import execute_in_sandbox

    # Mock local host execution mode to verify bash subprocess execution safely
    os.environ["VULNCATCHER_SANDBOX_MODE"] = "local"
    try:
        code = "#!/bin/sh\ncheck_func() {\n    echo 'active'\n}\n"
        payload = '. ./target.sh\necho "Payload verified: $(check_func)"\n'
        res = execute_in_sandbox(code, payload, "bash")

        assert res["status"] == "success"
        assert res["exit_code"] == 0
        assert "Payload verified: active" in res["stdout"].strip()
        assert res["mode_used"] == "local"
    finally:
        del os.environ["VULNCATCHER_SANDBOX_MODE"]


def test_apply_patch_unified_diff(tmp_path: Path):
    from app.remediation import apply_patch

    target_file = tmp_path / "app.py"
    target_file.write_text("def run():\n    print('hello old')\n")

    diff = (
        "--- app.py\n"
        "+++ app.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def run():\n"
        "-    print('hello old')\n"
        "+    print('hello new')\n"
    )

    res = apply_patch(str(target_file), diff)

    assert res["status"] == "success"
    assert res["exit_code"] == 0
    assert "hello new" in target_file.read_text()


def test_map_boundaries_web(tmp_path: Path):
    import os

    from app.tools import map_boundaries

    boot_path = os.path.abspath("app/.adk/bootstrapped_signatures.json")
    if os.path.exists(boot_path):
        os.remove(boot_path)

    # Create mock web project
    routes_file = tmp_path / "routes.js"
    routes_file.write_text("const router = express.Router();\n")

    res = map_boundaries(str(tmp_path))
    assert res["status"] == "success"
    assert res["category"] == "web"
    assert str(routes_file) in res["boundary_files"]


def test_map_boundaries_systems(tmp_path: Path):
    import os

    from app.tools import map_boundaries

    boot_path = os.path.abspath("app/.adk/bootstrapped_signatures.json")
    if os.path.exists(boot_path):
        os.remove(boot_path)

    # Create mock systems driver project
    driver_file = tmp_path / "driver.c"
    driver_file.write_text(
        "static struct file_operations my_fops = {\n"
        "    .unlocked_ioctl = my_ioctl,\n"
        "};\n"
    )

    res = map_boundaries(str(tmp_path))
    assert res["status"] == "success"
    assert res["category"] == "systems"
    assert str(driver_file) in res["boundary_files"]


def test_execute_in_sandbox_auto_mock_mongoose():
    import os

    from app.sandbox import execute_in_sandbox

    os.environ["VULNCATCHER_SANDBOX_MODE"] = "local"
    try:
        # Replicates dynamic stub written by Validation Agent at runtime!
        code = (
            "try {\n"
            "    const Module = require('module');\n"
            "    const originalRequire = Module.prototype.require;\n"
            "    Module.prototype.require = function(name) {\n"
            "        if (name === 'mongoose') {\n"
            "            return {\n"
            "                connect: () => Promise.resolve(),\n"
            "                model: () => ({ find: () => ({ exec: () => "
            "Promise.resolve([]) }) })\n"
            "            };\n"
            "        }\n"
            "        return originalRequire.apply(this, arguments);\n"
            "    };\n"
            "} catch(e) {}\n"
            "\n"
            "const mongoose = require('mongoose');\n"
            "mongoose.connect('mongodb://localhost:27017/test').then(() => {\n"
            "    const User = mongoose.model('User');\n"
            "    User.find().exec().then(res => {\n"
            "        console.log('Mock query result:', JSON.stringify(res));\n"
            "    });\n"
            "});\n"
        )
        payload = (
            "require('./target.js'); "
            "console.log('Mocking validation complete');\n"
        )

        res = execute_in_sandbox(code, payload, "javascript")

        assert res["status"] == "success"
        assert res["exit_code"] == 0
        assert "Mock query result: []" in res["stdout"]
    finally:
        del os.environ["VULNCATCHER_SANDBOX_MODE"]


def test_calculate_session_token_costs():
    import json
    import os
    import sqlite3

    from app.cli.costs import calculate_session_token_costs

    db_path = str(
        Path(__file__).parent.parent.parent / "app" / ".adk" / "session.db"
    )
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    # Create mock event tables in test context
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TABLE IF EXISTS events_test_temp;")
    conn.execute(
        "CREATE TABLE events_test_temp ("
        "session_id TEXT, model_version TEXT, event_data TEXT);"
    )

    mock_event_pro = {
        "model_version": "gemini-3.1-pro-preview",
        "usage_metadata": {
            "prompt_token_count": 1000,
            "candidates_token_count": 200,
        },
    }
    mock_event_flash = {
        "model_version": "gemini-3.5-flash",
        "usage_metadata": {
            "prompt_token_count": 5000,
            "candidates_token_count": 500,
        },
    }

    conn.execute(
        "INSERT INTO events_test_temp VALUES (?, ?, ?);",
        ("test-session", "gemini-3.1-pro-preview", json.dumps(mock_event_pro)),
    )
    conn.execute(
        "INSERT INTO events_test_temp VALUES (?, ?, ?);",
        ("test-session", "gemini-3.5-flash", json.dumps(mock_event_flash)),
    )
    conn.commit()

    # Backup original events data if exists to prevent collision
    has_events = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events';"
    ).fetchone()
    if has_events:
        conn.execute("ALTER TABLE events RENAME TO events_backup_temp;")
    conn.execute("ALTER TABLE events_test_temp RENAME TO events;")
    conn.close()

    os.environ["VULNCATCHER_ENTERPRISE_DISCOUNT"] = "0.30"
    try:
        stats = calculate_session_token_costs("test-session")
        assert stats is not None
        assert stats["pro_in"] == 1000
        assert stats["pro_out"] == 200
        assert stats["flash_in"] == 5000
        assert stats["flash_out"] == 500
        assert stats["total_cost"] > 0.0
        assert "Discount of 30%" in stats["discount_label"]
    finally:
        del os.environ["VULNCATCHER_ENTERPRISE_DISCOUNT"]
        # Restore original events data
        conn = sqlite3.connect(db_path)
        conn.execute("DROP TABLE IF EXISTS events;")
        if has_events:
            conn.execute("ALTER TABLE events_backup_temp RENAME TO events;")
        conn.close()


def test_verify_model_configurations():
    import json
    import os

    from app.agent import _model, _model_fast

    # 1. Retrieve active model names dynamically
    pro_model = _model().model
    flash_model = _model_fast().model

    # 2. Verify model name guidelines
    assert pro_model.startswith("gemini-")
    assert flash_model.startswith("gemini-")

    # 3. Verify pricing registry has these model mappings configured
    prices_path = os.path.abspath("app/app_utils/default_prices.json")
    assert os.path.exists(prices_path)
    with open(prices_path, encoding="utf-8") as f:
        prices = json.load(f)

    assert pro_model in prices["models"]
    assert flash_model in prices["models"]
