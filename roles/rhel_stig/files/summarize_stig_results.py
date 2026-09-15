#!/usr/bin/env python3
"""Summarize OpenSCAP XCCDF result XML into a readable text report."""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def load_rule_results(path: Path) -> dict[str, dict]:
    """Return {rule_id: {result, messages, severity}} for rule-result elements."""
    # Huge result files: stream parse for memory safety on small instances.
    results: dict[str, dict] = {}
    context = ET.iterparse(str(path), events=("end",))
    for _event, elem in context:
        if local(elem.tag) != "rule-result":
            continue
        rule_id = elem.attrib.get("idref", "")
        if not rule_id:
            elem.clear()
            continue
        result_el = None
        messages = []
        for child in elem:
            name = local(child.tag)
            if name == "result":
                result_el = (child.text or "").strip()
            elif name == "message" and child.text:
                messages.append(re.sub(r"\s+", " ", child.text).strip())
        # Keep first occurrence that is an actual evaluated result when duplicates exist
        # (profile select entries can appear elsewhere; rule-result is what we want).
        if rule_id not in results or results[rule_id]["result"] in {"", "notselected"}:
            results[rule_id] = {
                "result": result_el or "unknown",
                "messages": messages,
                "severity": elem.attrib.get("severity", ""),
            }
        elem.clear()
    return results


def short_id(rule_id: str) -> str:
    return rule_id.replace("xccdf_org.ssgproject.content_rule_", "")


def format_counts(results: dict[str, dict]) -> str:
    counts = Counter(v["result"] for v in results.values())
    order = ["pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational"]
    lines = []
    for key in order:
        if key in counts:
            lines.append(f"  {key:16} {counts[key]}")
    for key, value in sorted(counts.items()):
        if key not in order:
            lines.append(f"  {key:16} {value}")
    return "\n".join(lines) if lines else "  (no rule-results found)"


def interesting(results: dict[str, dict]) -> list[tuple[str, dict]]:
    """Rules that failed/errored (exclude notselected noise)."""
    keep = {"fail", "error", "unknown"}
    items = [(rid, data) for rid, data in results.items() if data["result"] in keep]
    return sorted(items, key=lambda x: (x[1]["result"], short_id(x[0])))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pre", required=True, type=Path)
    parser.add_argument("--post", required=True, type=Path)
    parser.add_argument("--remediate", type=Path)
    parser.add_argument("--focus-rule", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    sections = []
    pre = load_rule_results(args.pre) if args.pre.exists() else {}
    post = load_rule_results(args.post) if args.post.exists() else {}
    rem = load_rule_results(args.remediate) if args.remediate and args.remediate.exists() else {}

    sections.append("STIG OpenSCAP Summary")
    sections.append("=" * 72)
    sections.append("")
    sections.append(f"Focus rule: {args.focus_rule}")
    sections.append(f"  short id:  {short_id(args.focus_rule)}")
    sections.append("")

    def focus_line(label: str, bag: dict[str, dict]) -> str:
        data = bag.get(args.focus_rule)
        if not data:
            return f"  {label:12} NOT FOUND in results"
        msg = f"  {label:12} {data['result']}"
        if data["messages"]:
            msg += f" — {data['messages'][0]}"
        return msg

    sections.append("Focus rule status")
    sections.append("-" * 72)
    sections.append(focus_line("pre-scan", pre))
    if rem:
        sections.append(focus_line("remediate", rem))
    sections.append(focus_line("post-scan", post))
    sections.append("")

    pre_r = pre.get(args.focus_rule, {}).get("result")
    post_r = post.get(args.focus_rule, {}).get("result")
    if pre_r == "fail" and post_r == "pass":
        verdict = "SUCCESS — focus rule went fail → pass"
    elif pre_r == post_r == "pass":
        verdict = "ALREADY COMPLIANT — focus rule was already pass"
    elif rem.get(args.focus_rule, {}).get("result") == "error":
        verdict = "REMEDIATION ERROR — focus rule fix did not run (see remediate messages)"
    else:
        verdict = f"NOT FIXED — focus rule pre={pre_r} post={post_r}"
    sections.append(f"Verdict: {verdict}")
    sections.append("")

    sections.append("Pre-scan counts")
    sections.append("-" * 72)
    sections.append(format_counts(pre))
    sections.append("")
    sections.append("Post-scan counts")
    sections.append("-" * 72)
    sections.append(format_counts(post))
    sections.append("")

    sections.append("Failed / error rules (post-scan)")
    sections.append("-" * 72)
    post_bad = interesting(post)
    if not post_bad:
        sections.append("  (none)")
    else:
        for rid, data in post_bad:
            line = f"  [{data['result']}] {short_id(rid)}"
            sections.append(line)
            for message in data["messages"][:3]:
                sections.append(f"           why: {message}")
    sections.append("")

    if rem:
        sections.append("Failed / error rules (remediate run)")
        sections.append("-" * 72)
        rem_bad = interesting(rem)
        if not rem_bad:
            sections.append("  (none)")
        else:
            for rid, data in rem_bad:
                line = f"  [{data['result']}] {short_id(rid)}"
                sections.append(line)
                for message in data["messages"][:3]:
                    sections.append(f"           why: {message}")
        sections.append("")

    sections.append("HTML reports (open in a browser)")
    sections.append("-" * 72)
    sections.append("  pre-scan-report.html")
    sections.append("  remediate-report.html")
    sections.append("  post-scan-report.html")
    sections.append("")

    text = "\n".join(sections) + "\n"
    args.output.write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
