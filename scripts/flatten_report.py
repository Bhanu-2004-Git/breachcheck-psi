#!/usr/bin/env python3
"""Inline every \\input{generated/...} of report/report.tex into one file
(report/report_flat.tex) so it can be pasted into Overleaf together with the
three figure PDFs from report/generated/."""
import os
import re
import sys

src = sys.argv[1] if len(sys.argv) > 1 else os.path.join("report", "report.tex")
dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join("report", "report_flat.tex")
base = os.path.dirname(src)
text = open(src).read()


def repl(m):
    path = os.path.join(base, m.group(1))
    if not path.endswith(".tex"):
        path += ".tex"
    body = open(path).read().rstrip("\n")
    return f"% ---- begin {m.group(1)} (generated from results/*.json) ----\n{body}\n% ---- end {m.group(1)} ----"


text = re.sub(r"\\(?:input|tabin)\{(generated/[^}]+)\}", repl, text)
text = text.replace(r"\graphicspath{{generated/}}", r"\graphicspath{{generated/}{./}}")
open(dst, "w").write(text)
print("wrote", dst)
