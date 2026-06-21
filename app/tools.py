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
"""Tools exposed to the VulnCatcher sub-agents.

V0 walking skeleton: Semgrep is real; Trivy/Gitleaks/Bandit are stubs that return
empty findings so the pipeline shape is exercised end-to-end.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

try:
    from tree_sitter import Language, Parser, Query, QueryCursor

    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

_TS_LANGUAGES = {}

if HAS_TREE_SITTER:
    try:
        import tree_sitter_python as tspython

        _TS_LANGUAGES["python"] = Language(tspython.language())
    except ImportError:
        pass

    try:
        import tree_sitter_javascript as tsjavascript

        _TS_LANGUAGES["javascript"] = Language(tsjavascript.language())
    except ImportError:
        pass

    try:
        import tree_sitter_java as tsjava

        _TS_LANGUAGES["java"] = Language(tsjava.language())
    except ImportError:
        pass

    try:
        import tree_sitter_go as tsgo

        _TS_LANGUAGES["go"] = Language(tsgo.language())
    except ImportError:
        pass

    try:
        import tree_sitter_c as tsc

        _TS_LANGUAGES["c"] = Language(tsc.language())
    except ImportError:
        pass

    try:
        import tree_sitter_cpp as tscpp

        _TS_LANGUAGES["cpp"] = Language(tscpp.language())
    except ImportError:
        pass

    try:
        import tree_sitter_rust as tsrust

        _TS_LANGUAGES["rust"] = Language(tsrust.language())
    except ImportError:
        pass

    try:
        import tree_sitter_ruby as tsruby

        _TS_LANGUAGES["ruby"] = Language(tsruby.language())
    except ImportError:
        pass

    try:
        import tree_sitter_php as tsphp

        _TS_LANGUAGES["php"] = Language(tsphp.language_php())
    except ImportError:
        pass

    try:
        import tree_sitter_c_sharp as tscsharp

        _TS_LANGUAGES["csharp"] = Language(tscsharp.language())
    except ImportError:
        pass

    try:
        import tree_sitter_typescript as tstypescript

        _TS_LANGUAGES["typescript"] = Language(
            tstypescript.language_typescript()
        )
    except ImportError:
        pass

    try:
        import tree_sitter_html as tshtml

        _TS_LANGUAGES["html"] = Language(tshtml.language())
    except ImportError:
        pass

    try:
        import tree_sitter_css as tscss

        _TS_LANGUAGES["css"] = Language(tscss.language())
    except ImportError:
        pass

    try:
        import tree_sitter_json as tsjson

        _TS_LANGUAGES["json"] = Language(tsjson.language())
    except ImportError:
        pass

ALLOWED_BINARIES = frozenset({"semgrep", "trivy", "gitleaks", "bandit"})
SCANNER_TIMEOUT_S = 300
REPORTS_DIR = Path(
    os.environ.get("VULNCATCHER_REPORTS_DIR", "./reports")
).resolve()

EXPLORATION_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        "reports",
    }
)
GREP_MAX_MATCHES = 100
GREP_TIMEOUT_S = 60
LIST_DIR_MAX_ENTRIES = 500
TRIVY_MAX_FINDINGS = 50
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SKILLS_DIR = Path(__file__).parent / "skills"


def _parse_skill_frontmatter(text: str) -> dict:
    """Parse a tiny YAML-ish frontmatter block. Supports name/description/when_to_apply/file_globs."""
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}
    meta: dict = {}
    for raw in text[4:end].splitlines():
        if ":" not in raw:
            continue
        key, _, val = raw.partition(":")
        meta[key.strip()] = val.strip()
    return meta


def _build_skill_index(category: str) -> str:
    """Build a human-readable skill index for injection into an agent's instruction.

    Returns one line per skill: `- {skill_id}: {description}`. Reads frontmatter only.
    """
    cat_dir = SKILLS_DIR / category
    if not cat_dir.is_dir():
        return "(no skills available)"
    entries: list[str] = []
    for path in sorted(cat_dir.glob("*.md")):
        meta = _parse_skill_frontmatter(path.read_text())
        skill_id = meta.get("name") or path.stem
        desc = meta.get("description") or "(no description)"
        entries.append(f"- {skill_id}: {desc}")
    return "\n".join(entries) if entries else "(no skills available)"


def _exec_scanner(binary: str, args: list[str], cwd: str | None = None) -> dict:
    """Run an allowlisted scanner binary as a subprocess. Internal helper."""
    if binary not in ALLOWED_BINARIES:
        return {
            "status": "blocked",
            "error": f"binary {binary!r} not in allowlist",
        }
    abs_path = shutil.which(binary)
    if not abs_path:
        return {"status": "not_installed", "binary": binary}
    try:
        proc = subprocess.run(
            [abs_path, *args],
            capture_output=True,
            text=True,
            timeout=SCANNER_TIMEOUT_S,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "binary": binary,
            "timeout_s": SCANNER_TIMEOUT_S,
        }
    return {
        "status": "ran",
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
    }


def detect_languages(target_path: str) -> dict:
    """Detect probable languages in a target codebase via manifest heuristics.

    Args:
        target_path: Absolute or working-dir-relative path to the codebase root.

    Returns:
        dict with 'status' and 'languages' (sorted list of language identifiers).
    """
    p = Path(target_path)
    if not p.is_dir():
        return {"status": "error", "error": f"not a directory: {target_path}"}
    manifests = {
        "package.json": "javascript",
        "tsconfig.json": "typescript",
        "requirements.txt": "python",
        "pyproject.toml": "python",
        "Pipfile": "python",
        "setup.py": "python",
        "go.mod": "go",
        "Cargo.toml": "rust",
        "pom.xml": "java",
        "build.gradle": "java",
        "Gemfile": "ruby",
        "composer.json": "php",
        "Package.swift": "swift",
    }
    found: set[str] = set()
    for root_dir, dirs, files in os.walk(p):
        dirs[:] = [d for d in dirs if d not in EXPLORATION_SKIP_DIRS]
        for fname in files:
            if fname in manifests:
                found.add(manifests[fname])
        if found == set(manifests.values()):
            break  # All languages detected, no need to keep walking
    return {"status": "success", "languages": sorted(found)}


_SCANNER_CACHE = {}


def run_semgrep(target_path: str) -> dict:
    """Run Semgrep SAST against target_path with the auto config.

    Args:
        target_path: Path to the codebase root to scan.

    Returns:
        dict with 'status', 'count', and 'findings' (list of normalized findings).
    """
    abs_target = os.path.abspath(target_path)
    cache_key = ("semgrep", abs_target)
    if cache_key in _SCANNER_CACHE:
        return _SCANNER_CACHE[cache_key]
    result = _exec_scanner(
        "semgrep",
        [
            "scan",
            "--json",
            "--config=p/default",
            "--quiet",
            "--metrics=off",
            "--no-git-ignore",
            target_path,
        ],
    )
    if result["status"] != "ran":
        return result
    try:
        parsed = json.loads(result["stdout"] or "{}")
    except json.JSONDecodeError as e:
        return {
            "status": "parse_error",
            "error": str(e),
            "raw": result["stdout"][:500],
        }
    findings = []
    SEMEGREP_SEVERITY_MAP = {
        "error": "error",
        "warning": "warning",
        "info": "note",
    }
    for r in parsed.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe_field = meta.get("cwe") or []
        if isinstance(cwe_field, str):
            cwe_field = [cwe_field]

        severity_str = str(extra.get("severity", "info")).lower()
        level = SEMEGREP_SEVERITY_MAP.get(severity_str, "note")

        findings.append(
            {
                "ruleId": r.get("check_id", "unknown"),
                "level": level,
                "message": {"text": extra.get("message", "")[:500]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": r.get("path", "?")},
                            "region": {
                                "startLine": r.get("start", {}).get("line", 0)
                            },
                        }
                    }
                ],
                "properties": {
                    "scanner": "semgrep",
                    "cwe": cwe_field,
                    "evidence": extra.get("lines", "")[:200],
                },
            }
        )
    res = {
        "status": "success",
        "scanner": "semgrep",
        "count": len(findings),
        "findings": findings,
    }
    _SCANNER_CACHE[cache_key] = res
    return res


def run_trivy(target_path: str) -> dict:
    """Run Trivy filesystem scan: vulnerable deps (CVEs) + secrets + IaC misconfig.

    Trivy downloads its vulnerability database from ghcr.io on first run and
    caches it under ~/.cache/trivy. Subsequent runs reuse the cache. This is
    the one documented exception to the agent's "no scanner network egress"
    constraint — see DESIGN_SPEC §Constraints.

    Findings are normalized to the common schema and capped at
    TRIVY_MAX_FINDINGS, sorted by severity (critical first), so a noisy npm
    `node_modules` tree doesn't blow up triage's context.

    Args:
        target_path: Path to the codebase root to scan.

    Returns:
        dict with 'status', 'count', 'truncated' (bool), and 'findings'
        (list of normalized findings).
    """
    abs_target = os.path.abspath(target_path)
    cache_key = ("trivy", abs_target)
    if cache_key in _SCANNER_CACHE:
        return _SCANNER_CACHE[cache_key]
    result = _exec_scanner(
        "trivy",
        [
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln,secret,misconfig",
            "--quiet",
            target_path,
        ],
    )
    if result["status"] != "ran":
        return result
    try:
        parsed = json.loads(result["stdout"] or "{}")
    except json.JSONDecodeError as e:
        return {
            "status": "parse_error",
            "error": str(e),
            "raw": result["stdout"][:500],
        }

    findings: list[dict] = []
    TRIVY_SEVERITY_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "warning",
        "info": "note",
        "unknown": "note",
    }
    for res in parsed.get("Results", []) or []:
        target = res.get("Target", "?")
        for v in res.get("Vulnerabilities", []) or []:
            sev_str = str(v.get("Severity") or "info").lower()
            level = TRIVY_SEVERITY_MAP.get(sev_str, "note")
            findings.append(
                {
                    "ruleId": f"trivy.vuln.{v.get('VulnerabilityID', 'unknown')}",
                    "level": level,
                    "message": {
                        "text": (v.get("Title") or v.get("Description") or "")[
                            :500
                        ]
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target},
                                "region": {"startLine": 0},
                            }
                        }
                    ],
                    "properties": {
                        "scanner": "trivy",
                        "cwe": v.get("CweIDs") or [],
                        "package": v.get("PkgName"),
                        "installed_version": v.get("InstalledVersion"),
                        "fixed_version": v.get("FixedVersion"),
                    },
                }
            )
        for s in res.get("Secrets", []) or []:
            sev_str = str(s.get("Severity") or "high").lower()
            level = TRIVY_SEVERITY_MAP.get(sev_str, "error")
            findings.append(
                {
                    "ruleId": f"trivy.secret.{s.get('RuleID', 'unknown')}",
                    "level": level,
                    "message": {
                        "text": (s.get("Title") or s.get("Match", ""))[:500]
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target},
                                "region": {
                                    "startLine": s.get("StartLine") or 0
                                },
                            }
                        }
                    ],
                    "properties": {
                        "scanner": "trivy",
                        "cwe": ["CWE-798"],
                        "evidence": s.get("Match", "")[:200],
                    },
                }
            )
        for m in res.get("Misconfigurations", []) or []:
            sev_str = str(m.get("Severity") or "info").lower()
            level = TRIVY_SEVERITY_MAP.get(sev_str, "note")
            cause = m.get("CauseMetadata") or {}
            findings.append(
                {
                    "ruleId": f"trivy.misconfig.{m.get('ID', 'unknown')}",
                    "level": level,
                    "message": {
                        "text": (m.get("Title") or m.get("Description", ""))[
                            :500
                        ]
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target},
                                "region": {
                                    "startLine": cause.get("StartLine") or 0
                                },
                            }
                        }
                    ],
                    "properties": {
                        "scanner": "trivy",
                        "cwe": [],
                    },
                }
            )

    LEVEL_RANK = {"error": 3, "warning": 2, "note": 1}
    findings.sort(
        key=lambda f: LEVEL_RANK.get(str(f.get("level", "note")), 0),
        reverse=True,
    )
    truncated = len(findings) > TRIVY_MAX_FINDINGS
    findings = findings[:TRIVY_MAX_FINDINGS]

    res = {
        "status": "success",
        "scanner": "trivy",
        "count": len(findings),
        "truncated": truncated,
        "findings": findings,
    }
    _SCANNER_CACHE[cache_key] = res
    return res


def run_gitleaks(target_path: str) -> dict:
    """Run Gitleaks dedicated secret scanner.

    Args:
        target_path: Path to the codebase root to scan.

    Returns:
        dict with 'status', 'count', and 'findings' (list of normalized findings).
    """
    abs_target = os.path.abspath(target_path)
    cache_key = ("gitleaks", abs_target)
    if cache_key in _SCANNER_CACHE:
        return _SCANNER_CACHE[cache_key]
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_report_path = tf.name

    try:
        result = _exec_scanner(
            "gitleaks",
            [
                "detect",
                "--source",
                target_path,
                "--no-git",
                "--report-format",
                "json",
                "--report-path",
                temp_report_path,
            ],
        )
        if result["status"] != "ran":
            return result
        if result["returncode"] not in (0, 1):
            return {
                "status": "error",
                "error": f"gitleaks failed with exit code {result['returncode']}",
                "stderr": result["stderr"][:500],
            }

        parsed = []
        if (
            os.path.exists(temp_report_path)
            and os.path.getsize(temp_report_path) > 0
        ):
            try:
                with open(temp_report_path, "r") as rf:
                    parsed = json.load(rf)
            except Exception as e:
                return {
                    "status": "parse_error",
                    "error": f"Failed to parse gitleaks JSON report: {e}",
                }
        elif result.get("stdout"):
            # Fallback for unit testing/mocking where output is returned in stdout
            try:
                stdout_str = result["stdout"].strip()
                parsed = json.loads(stdout_str) if stdout_str else []
            except Exception as e:
                return {
                    "status": "parse_error",
                    "error": f"Failed to parse gitleaks JSON stdout fallback: {e}",
                }
    finally:
        if os.path.exists(temp_report_path):
            try:
                os.remove(temp_report_path)
            except Exception:
                pass

    findings = []
    for r in parsed:
        findings.append(
            {
                "ruleId": f"gitleaks.secret.{r.get('RuleID', 'unknown')}",
                "level": "error",
                "message": {
                    "text": r.get("Description", "Secret leaked")[:500]
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": r.get("File", "?")},
                            "region": {"startLine": r.get("StartLine", 0)},
                        }
                    }
                ],
                "properties": {
                    "scanner": "gitleaks",
                    "cwe": ["CWE-798"],
                    "evidence": r.get("Match", "")[:200],
                },
            }
        )

    res = {
        "status": "success",
        "scanner": "gitleaks",
        "count": len(findings),
        "findings": findings,
    }
    _SCANNER_CACHE[cache_key] = res
    return res


def run_bandit(target_path: str) -> dict:
    """Run Bandit Python SAST against target_path.

    Args:
        target_path: Path to the codebase root to scan.

    Returns:
        dict with 'status', 'count', and 'findings' (list of normalized findings).
    """
    abs_target = os.path.abspath(target_path)
    cache_key = ("bandit", abs_target)
    if cache_key in _SCANNER_CACHE:
        return _SCANNER_CACHE[cache_key]
    result = _exec_scanner(
        "bandit",
        [
            "-r",
            target_path,
            "--format",
            "json",
            "--quiet",
        ],
    )
    if result["status"] != "ran":
        return result
    if result["returncode"] not in (0, 1):
        return {
            "status": "error",
            "error": f"bandit failed with exit code {result['returncode']}",
            "stderr": result["stderr"][:500],
        }

    try:
        parsed = json.loads(result["stdout"] or "{}")
    except json.JSONDecodeError as e:
        return {
            "status": "parse_error",
            "error": str(e),
            "raw": result["stdout"][:500],
        }

    findings = []
    BANDIT_SEVERITY_MAP = {
        "high": "error",
        "medium": "warning",
        "low": "note",
        "undefined": "note",
    }
    for r in parsed.get("results", []):
        sev_str = str(r.get("issue_severity") or "undefined").lower()
        level = BANDIT_SEVERITY_MAP.get(sev_str, "note")

        cwe_id = r.get("issue_cwe", {}).get("id")
        cwe_field = [f"CWE-{cwe_id}"] if cwe_id else []

        findings.append(
            {
                "ruleId": f"bandit.sast.{r.get('test_id', 'unknown')}",
                "level": level,
                "message": {"text": r.get("issue_text", "")[:500]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": r.get("filename", "?")},
                            "region": {"startLine": r.get("line_number", 0)},
                        }
                    }
                ],
                "properties": {
                    "scanner": "bandit",
                    "cwe": cwe_field,
                    "evidence": r.get("code", "")[:200],
                },
            }
        )

    res = {
        "status": "success",
        "scanner": "bandit",
        "count": len(findings),
        "findings": findings,
    }
    _SCANNER_CACHE[cache_key] = res
    return res


def list_dir(target_path: str, max_depth: int = 2) -> dict:
    """List files and directories under target_path, capped in depth and breadth.

    Skips common noise directories (.git, node_modules, __pycache__, virtualenvs).
    Use this to get a structural overview of a codebase before deeper inspection.

    Args:
        target_path: Directory to list.
        max_depth: How many levels to descend (1 = just target_path's children).

    Returns:
        dict with 'status', 'root', 'truncated' (bool), and 'entries' (list of
        objects with 'path' relative to root, 'type' = 'file'|'dir', and 'size'
        for files).
    """
    root = Path(target_path)
    if not root.is_dir():
        return {"status": "error", "error": f"not a directory: {target_path}"}
    max_depth = max(1, min(max_depth, 6))
    entries: list[dict] = []
    truncated = False

    def walk(d: Path, depth: int) -> None:
        nonlocal truncated
        if depth > max_depth or truncated:
            return
        try:
            children = sorted(d.iterdir())
        except OSError:
            return
        for child in children:
            if child.name in EXPLORATION_SKIP_DIRS:
                continue
            rel = str(child.relative_to(root))
            if child.is_dir():
                entries.append({"path": rel, "type": "dir"})
                if len(entries) >= LIST_DIR_MAX_ENTRIES:
                    truncated = True
                    return
                walk(child, depth + 1)
            elif child.is_file():
                try:
                    size = child.stat().st_size
                except OSError:
                    size = -1
                entries.append({"path": rel, "type": "file", "size": size})
                if len(entries) >= LIST_DIR_MAX_ENTRIES:
                    truncated = True
                    return

    walk(root, 1)
    return {
        "status": "success",
        "root": str(root.resolve()),
        "truncated": truncated,
        "entries": entries,
    }


def grep_code(
    pattern: str,
    target_path: str,
    file_extensions: list[str] | None = None,
) -> dict:
    """Search for a regex pattern across files under target_path.

    Uses ripgrep when available for speed; falls back to a Python re walk.
    Skips common noise directories. Caps results at 100 matches.

    Args:
        pattern: Regex pattern (Python re syntax; ripgrep accepts most of it too).
        target_path: Root directory to search.
        file_extensions: Optional list of extensions to restrict to, e.g.
            ["py", "js"]. Pass None to search all files.

    Returns:
        dict with 'status', 'count', 'truncated' (bool), and 'matches' (list of
        objects with 'file', 'line', 'snippet').
    """
    root = Path(target_path)
    if not root.is_dir():
        return {"status": "error", "error": f"not a directory: {target_path}"}

    rg = shutil.which("rg")
    matches: list[dict] = []
    truncated = False

    if rg:
        args = [
            rg,
            "--no-heading",
            "--line-number",
            "--max-count",
            "20",
            "--max-columns",
            "300",
        ]
        for skip in EXPLORATION_SKIP_DIRS:
            args.extend(["--glob", f"!{skip}"])
        if file_extensions:
            for ext in file_extensions:
                args.extend(["--glob", f"*.{ext.lstrip('.')}"])
        args.extend([pattern, str(root)])
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=GREP_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "timeout_s": GREP_TIMEOUT_S}
        if proc.returncode not in (0, 1):
            return {"status": "error", "error": (proc.stderr or "")[:500]}
        for line in proc.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            file_, lineno, snippet = parts
            try:
                lineno_int = int(lineno)
            except ValueError:
                continue
            matches.append(
                {"file": file_, "line": lineno_int, "snippet": snippet[:300]}
            )
            if len(matches) >= GREP_MAX_MATCHES:
                truncated = True
                break
    else:
        try:
            regex = re.compile(pattern)
        except re.error as e:
            return {"status": "error", "error": f"bad pattern: {e}"}
        ext_set = (
            {f".{e.lstrip('.')}" for e in file_extensions}
            if file_extensions
            else None
        )
        for path in root.rglob("*"):
            if truncated:
                break
            if any(part in EXPLORATION_SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if ext_set and path.suffix not in ext_set:
                continue
            try:
                with path.open("r", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if regex.search(line):
                            matches.append(
                                {
                                    "file": str(path),
                                    "line": i,
                                    "snippet": line.rstrip("\n")[:300],
                                }
                            )
                            if len(matches) >= GREP_MAX_MATCHES:
                                truncated = True
                                break
            except OSError:
                continue

    return {
        "status": "success",
        "count": len(matches),
        "truncated": truncated,
        "matches": matches,
    }


def load_skill(skill_id: str, category: str = "detection") -> dict:
    """Load a vulnerability-detection skill from app/skills/<category>/<skill_id>.md.

    Skills are progressively-disclosed playbooks: each one describes how to detect
    a specific vulnerability class (CSRF, SSRF, IDOR, etc.) with the patterns to
    grep for, files to inspect, true-positive criteria, and false-positive caveats.
    Call this after consulting the skill index in your instruction to pull only
    the skills you decide apply to the current codebase.

    Args:
        skill_id: The skill identifier (filename without .md), e.g. 'csrf' or 'idor'.
        category: Skill category subdirectory under app/skills/. Defaults to 'detection'.

    Returns:
        dict with 'status', 'skill_id', and 'content' (full Markdown body of the
        skill, including frontmatter and procedure).
    """
    safe_id = Path(skill_id).name
    if (
        not safe_id
        or safe_id != skill_id
        or "/" in skill_id
        or ".." in skill_id
    ):
        return {"status": "error", "error": f"invalid skill_id: {skill_id!r}"}
    safe_category = Path(category).name
    if safe_category != category:
        return {"status": "error", "error": f"invalid category: {category!r}"}
    path = SKILLS_DIR / safe_category / f"{safe_id}.md"
    if not path.is_file():
        return {
            "status": "not_found",
            "skill_id": skill_id,
            "category": category,
        }
    return {
        "status": "success",
        "skill_id": skill_id,
        "category": category,
        "content": path.read_text(),
    }


def find_references(
    symbol: str,
    target_path: str,
    file_extensions: list[str] | None = None,
) -> dict:
    """Search for whole-word occurrences of a symbol (class, function, or variable) under target_path.

    Uses ripgrep when available for speed; falls back to a Python re walk.
    Skips common noise directories. Caps results at 100 matches.

    Args:
        symbol: The exact symbol name to search for (must consist of alphanumeric/underscores).
        target_path: Root directory to search.
        file_extensions: Optional list of extensions to restrict to, e.g. ["py", "js"].

    Returns:
        dict with 'status', 'count', 'truncated' (bool), and 'matches' (list of
        objects with 'file', 'line', 'snippet').
    """
    if not symbol or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", symbol):
        return {"status": "error", "error": f"invalid symbol name: {symbol!r}"}

    pattern = r"\b" + re.escape(symbol) + r"\b"
    return grep_code(pattern, target_path, file_extensions)


def read_code_window(file_path: str, start_line: int, end_line: int) -> dict:
    """Read a 1-indexed inclusive line range from a file. Capped at 200 lines.

    Args:
        file_path: Path to the source file.
        start_line: First line to include (1-indexed).
        end_line: Last line to include (1-indexed, inclusive).

    Returns:
        dict with 'status', 'file', 'start', 'end', and 'code' (string).
    """
    end_line = min(end_line, start_line + 200)
    p = Path(file_path)
    if not p.is_file():
        return {"status": "error", "error": f"not a file: {file_path}"}
    try:
        lines = p.read_text(errors="replace").splitlines()
    except OSError as e:
        return {"status": "error", "error": str(e)}
    snippet = "\n".join(lines[max(0, start_line - 1) : end_line])
    return {
        "status": "success",
        "file": file_path,
        "start": start_line,
        "end": end_line,
        "code": snippet,
    }


def query_ast(
    file_path: str,
    query_string: str,
    language: str,
) -> dict:
    """Execute a tree-sitter S-expression query against a source file's AST.

    Exposes structural code navigation to the agent. Supported languages: 'python', 'javascript', 'java', 'go', 'c', 'cpp'.

    Args:
        file_path: Path to the source file to query.
        query_string: S-expression query (e.g. '(function_definition name: (identifier) @name)').
        language: Parser language ('python', 'javascript', 'java', 'go', 'c', or 'cpp').

    Returns:
        dict with 'status', 'count', and 'matches' (list of objects with 'snippet', 'line', 'capture').
    """
    if not HAS_TREE_SITTER:
        return {
            "status": "not_installed",
            "error": "tree-sitter is not installed. Run 'uv pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-go tree-sitter-c tree-sitter-cpp' first.",
        }

    lang_lower = str(language).lower()
    if lang_lower not in _TS_LANGUAGES:
        return {
            "status": "error",
            "error": f"unsupported language: {language!r}. Supported: {list(_TS_LANGUAGES.keys())}",
        }

    p = Path(file_path)
    if not p.is_file():
        return {"status": "error", "error": f"not a file: {file_path}"}

    try:
        code_bytes = p.read_bytes()
    except OSError as e:
        return {"status": "error", "error": str(e)}

    lang = _TS_LANGUAGES[lang_lower]
    parser = Parser(lang)
    tree = parser.parse(code_bytes)

    try:
        query = Query(lang, query_string)
    except Exception as e:
        return {"status": "error", "error": f"invalid tree-sitter query: {e!s}"}

    cursor = QueryCursor(query)
    captures = cursor.captures(tree.root_node)
    matches = []
    for capture_name, nodes in captures.items():
        for node in nodes:
            snippet = node.text.decode("utf8", errors="replace")
            start_line = node.start_point[0] + 1
            matches.append(
                {
                    "snippet": snippet[:300],
                    "line": start_line,
                    "capture": capture_name,
                }
            )

    return {
        "status": "success",
        "count": len(matches),
        "matches": matches,
    }


def write_report(content: str, filename: str) -> dict:
    """Write a Markdown report under ./reports/. Path is sanitized.

    Args:
        content: Full Markdown body.
        filename: Desired filename. Path components are stripped; .md added if missing.

    Returns:
        dict with 'status', 'path' (absolute), and 'bytes' written.
    """
    REPORTS_DIR.mkdir(exist_ok=True)
    safe = Path(filename).name
    if not safe.endswith(".md"):
        safe = safe + ".md"
    out_path = (REPORTS_DIR / safe).resolve()
    if not str(out_path).startswith(str(REPORTS_DIR) + "/"):
        return {"status": "blocked", "error": "report path escapes ./reports/"}
    out_path.write_text(content)
    return {"status": "success", "path": str(out_path), "bytes": len(content)}


def map_boundaries(
    target_path: str,
    custom_patterns: list[str] = None,
    custom_filenames: list[str] = None,
) -> dict:
    """Dynamically analyze a codebase to harvest attack-surface entry points and system interface boundaries.

    Supports both Web/Endpoint codebases and Systems/Non-Endpoint codebases natively.

    Args:
        target_path: Absolute path to the repository to analyze.
        custom_patterns: Optional list of custom regex signatures generated dynamically by the agent.
        custom_filenames: Optional list of custom filename keywords to match.

    Returns:
        dict with 'status', 'category', and 'boundary_files' list.
    """
    if not os.path.exists(target_path):
        return {"status": "error", "error": f"Path not found: {target_path}"}

    boundary_files = []
    category = "unknown"

    # Common noise directories to exclude from walks
    exclude_dirs = {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "target",
        "build",
        "dist",
        ".adk",
        "reports",
    }

    # Binary / asset extensions to skip before attempting file reads
    _SKIP_EXTENSIONS = frozenset(
        {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".ico",
            ".svg",
            ".webp",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".otf",
            ".pdf",
            ".zip",
            ".tar",
            ".gz",
            ".bz2",
            ".7z",
            ".rar",
            ".exe",
            ".dll",
            ".so",
            ".dylib",
            ".o",
            ".a",
            ".class",
            ".pyc",
            ".pyo",
            ".map",
            ".min.js",
            ".min.css",
            ".lock",
            ".sum",
            ".mp3",
            ".mp4",
            ".avi",
            ".mov",
            ".wav",
            ".flac",
            ".db",
            ".sqlite",
            ".sqlite3",
            ".DS_Store",
        }
    )

    sig_path = str(
        Path(__file__).parent / "app_utils" / "framework_signatures.json"
    )
    web_patterns_list = []
    web_filenames = set()
    sys_patterns_list = []
    sys_filenames = set()

    # Fallback registries for IaC config files (overridden dynamically from configuration registry!)
    iac_extensions = {".tf", ".tfvars", ".jsonnet"}
    iac_filenames = {
        "serverless.yml",
        "serverless.yaml",
        "cdk.json",
        "template.yaml",
        "template.yml",
    }

    if os.path.exists(sig_path):
        try:
            with open(sig_path) as f:
                sig_data = json.load(f)

            all_web_patterns = []
            all_web_filenames = set()
            all_sys_patterns = []
            all_sys_filenames = set()
            all_iac_extensions = set()
            all_iac_filenames = set()

            for cat, cat_data in sig_data.items():
                if not isinstance(cat_data, dict):
                    continue

                if cat == "systems":
                    all_sys_patterns.extend(cat_data.get("patterns", []))
                    all_sys_filenames.update(cat_data.get("filenames", []))
                elif cat == "iac":
                    all_iac_extensions.update(cat_data.get("extensions", []))
                    all_iac_filenames.update(cat_data.get("filenames", []))
                else:
                    # Polymorphic Resolution: Dynamically map any dynamic stacks (web, mobile, smart_contracts, etc.) into application boundary scopes!
                    all_web_patterns.extend(cat_data.get("patterns", []))
                    all_web_filenames.update(cat_data.get("filenames", []))

            web_patterns_list = all_web_patterns
            web_filenames = all_web_filenames
            sys_patterns_list = all_sys_patterns
            sys_filenames = all_sys_filenames
            iac_extensions = all_iac_extensions
            iac_filenames = all_iac_filenames
        except Exception:
            pass

    # Load bootstrapped signatures compiled dynamically by the AI Bootstrapper at startup
    boot_path = str(
        Path(__file__).parent / ".adk" / "bootstrapped_signatures.json"
    )
    if os.path.exists(boot_path):
        try:
            with open(boot_path) as f:
                boot_data = json.load(f)
                boot_cat = boot_data.get("category")
                if boot_data.get("patterns"):
                    if boot_cat == "systems":
                        sys_patterns_list = boot_data["patterns"]
                    else:
                        web_patterns_list = boot_data["patterns"]
                if boot_data.get("filenames"):
                    if boot_cat == "systems":
                        sys_filenames = set(boot_data["filenames"])
                    else:
                        web_filenames = set(boot_data["filenames"])
        except Exception:
            pass

    # Append dynamic custom entries passed by the agent
    if custom_patterns:
        # Place custom patterns under web or systems based on keyword cues
        for p in custom_patterns:
            if any(
                x in p.lower()
                for x in [
                    "syscall",
                    "ioctl",
                    "driver",
                    "kernel",
                    "socket",
                    "recv",
                ]
            ):
                sys_patterns_list.append(p)
            else:
                web_patterns_list.append(p)

    if custom_filenames:
        web_filenames.update(custom_filenames)

    # Compile regexes dynamically
    web_regex = (
        re.compile("|".join(web_patterns_list)) if web_patterns_list else None
    )
    sys_regex = (
        re.compile("|".join(sys_patterns_list)) if sys_patterns_list else None
    )

    web_matches = 0
    sys_matches = 0

    # Walk the target path
    for root, dirs, files in os.walk(target_path):
        # Exclude noise directories in-place
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, target_path)

            # 1. Check file names / paths for web endpoints
            path_parts = set(rel_path.replace("\\", "/").split("/"))
            if path_parts & web_filenames:
                boundary_files.append(file_path)
                web_matches += 1
                continue

            # 2. Check for Infrastructure-as-Code (IaC) config files dynamically
            _, ext = os.path.splitext(file.lower())
            if ext in iac_extensions or file.lower() in iac_filenames:
                boundary_files.append(file_path)
                continue

            # 2. Deep read to parse regex patterns — skip binary/asset files first
            _, ext = os.path.splitext(file.lower())
            if ext in _SKIP_EXTENSIONS:
                continue
            try:
                # Read only first 400 lines to keep it performant and fast
                with open(file_path, errors="ignore") as f:
                    head = "".join([f.readline() for _ in range(400)])

                # Check for web controllers imports
                if web_regex and web_regex.search(head):
                    boundary_files.append(file_path)
                    web_matches += 1

                # Check for systems / kernel boundaries
                if sys_regex and sys_regex.search(head):
                    boundary_files.append(file_path)
                    sys_matches += 1
            except Exception:
                pass

    # Determine codebase category based on match majority
    if web_matches > 0 or sys_matches > 0:
        if sys_matches >= web_matches:
            category = "systems"
        else:
            category = "web"

    return {
        "status": "success",
        "category": category,
        "boundary_files": [os.path.abspath(p) for p in boundary_files],
    }
