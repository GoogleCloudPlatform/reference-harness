---
name: xxe
description: Searches for XML External Entity (XXE) vulnerabilities where XML parsers are configured to evaluate external entities from unverified sources.
---

# Objective

Identify XML External Entity (XXE) vulnerabilities (CWE-611). XXE occurs when a
weakly configured XML parser processes XML input containing a reference to an
external entity. This can lead to local file inclusion, server-side request
forgery (SSRF), or Denial of Service (Billion Laughs attack).

## Methodology

You are acting as an expert application security reviewer hunting for CWE-611.

## Typical patterns to check

1.  Use `grep_code` to look for XML parsing functions:

- Python: `lxml.etree.parse(`, `xml.etree.ElementTree.parse(`, `minidom.parse(`
- Node.js: `libxmljs.parseXmlString(`, `xml2js.parseString(`

1.  Inspect the configuration options passed to these parsers.
1.  Trace whether the XML data originates from user input (e.g. `req.body`, file
    uploads, API payloads).

## True-positive signals

- The XML parser explicitly enables entity expansion (e.g.
  `resolve_entities=True` in lxml, or `noent: true` in Node libraries).
- The parser is a known unsafe legacy parser (e.g. Python's default
  `xml.etree.ElementTree` before secure defaults were introduced) and external
  entities are not explicitly disabled.

## False-positive signals (do NOT flag)

- The XML parser explicitly disables external entities or uses safe default
  configurations (e.g. `defusedxml` in Python).
- The XML being parsed is strictly server-controlled (e.g., parsing a local
  static config file).

## Output: severity guidance

- **Critical** if the XXE allows reading arbitrary local files or SSRF.
- **High** if the XXE only allows Denial of Service (Billion Laughs).

## Output: CWE

- `CWE-611` (Improper Restriction of XML External Entity Reference)

## Output: rule_id slug

- `ai.xxe-enabled` (XXE expansion is explicitly enabled on user data)
- `ai.xxe-unsafe-parser` (Use of an unsafe parser without explicit entity
  blocking)
