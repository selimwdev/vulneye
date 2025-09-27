#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report.py
تحويل نتائج JSON من pipeline لملف PDF احترافي بجداول منظمة.
Usage:
    python report.py input.json output.pdf
"""

import json
import sys
from typing import Any, Dict, List, Set

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

# إعداد ستايلات
BASE_STYLES = getSampleStyleSheet()
NORMAL = BASE_STYLES["Normal"]
HEADING1 = BASE_STYLES["Title"]
HEADING2 = BASE_STYLES["Heading2"]
HEADING3 = BASE_STYLES["Heading3"]

# Paragraph style مناسب للخلايا (يسمح باللف)
CELL_P = ParagraphStyle(
    "cell",
    parent=NORMAL,
    fontName="Helvetica",
    fontSize=9,
    leading=11,
    spaceAfter=3,
)

SMALL_P = ParagraphStyle(
    "small",
    parent=NORMAL,
    fontName="Helvetica",
    fontSize=8,
    leading=10,
)

# مساعدة: تأكد أن القيمة قابلة للطباعة داخل فقرة
def as_paragraph(value: Any) -> Paragraph:
    if value is None:
        text = "-"
    elif isinstance(value, bool):
        text = "True" if value else "False"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, list):
        text = ", ".join([str(x) for x in value]) if value else "-"
    elif isinstance(value, dict):
        text = ", ".join(f"{k}:{v}" for k, v in value.items())
    else:
        text = str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\n", "<br/>")
    return Paragraph(text, CELL_P)


# صنع جدول Key/Value من dict
def table_from_kv(d: Dict[str, Any], col_widths=(120 * mm, 70 * mm)) -> Table:
    rows = [["Key", "Value"]]
    for k, v in d.items():
        if isinstance(v, (dict, list)):
            rows.append([Paragraph(f"<b>{k}</b>", CELL_P), as_paragraph(v)])
        else:
            rows.append([Paragraph(str(k), CELL_P), as_paragraph(v)])
    t = Table(rows, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4b6eaf")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    return t


# صنع جدول من قائمة dicts
def table_from_list_of_dicts(list_of_dicts: List[Dict[str, Any]], max_cols_per_table: int = 6) -> List[Table]:
    if not list_of_dicts:
        return [Table([["(empty)"]])]

    keys: List[str] = []
    keyset: Set[str] = set()
    for item in list_of_dicts:
        for k in item.keys():
            if k not in keyset:
                keys.append(k)
                keyset.add(k)

    tables = []
    for i in range(0, len(keys), max_cols_per_table):
        chunk_keys = keys[i:i + max_cols_per_table]
        header = [Paragraph(str(k), CELL_P) for k in chunk_keys]
        rows = [header]

        for item in list_of_dicts:
            row = []
            for k in chunk_keys:
                v = item.get(k, "-")
                if isinstance(v, (dict, list)):
                    vtxt = json.dumps(v, indent=2)
                else:
                    vtxt = str(v)
                vtxt = vtxt.replace("\r\n", "\n").replace("\r", "\n")
                vtxt = vtxt.replace("\n", "<br/>")
                row.append(Paragraph(vtxt, SMALL_P))
            rows.append(row)

        col_widths = [25 * mm] * len(chunk_keys)

        t = Table(rows, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e5599")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ]
            )
        )
        tables.append(t)

    return tables


# الدالة الأساسية لبناء التقرير
def generate_report(data: Dict[str, Any], output_file: str = "scan_report.pdf"):
    doc = SimpleDocTemplate(output_file, pagesize=A4,
                            rightMargin=18 * mm, leftMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm)
    elements = []

    elements.append(Paragraph("Network Security Scan Report", HEADING1))
    elements.append(Spacer(1, 6))
    target = data.get("target", "-")
    duration = data.get("duration_seconds", "-")
    summary_line = f"<b>Target:</b> {target} &nbsp;&nbsp; <b>Scan Duration:</b> {duration} seconds"
    elements.append(Paragraph(summary_line, NORMAL))
    elements.append(Spacer(1, 8))

    open_ports = data.get("open_ports", [])
    if open_ports:
        elements.append(Paragraph("Open Ports Summary", HEADING2))
        port_rows = [["Port", "Status", "Service (if known)"]]
        port_service_map = {}
        ps = data.get("results", {}).get("Port Scanner", {})
        if isinstance(ps, dict):
            for item in ps.get("open_ports", []) if isinstance(ps.get("open_ports", []), list) else []:
                if isinstance(item, dict) and "port" in item:
                    port_service_map[item.get("port")] = item.get("service", "-")
        for p in open_ports:
            svc = port_service_map.get(p, "-")
            port_rows.append([Paragraph(str(p), CELL_P),
                              Paragraph("Open", CELL_P),
                              Paragraph(str(svc), CELL_P)])
        t_ports = Table(port_rows, colWidths=[40 * mm, 30 * mm, None],
                        hAlign="LEFT", repeatRows=1)
        t_ports.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6b8cc6")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ]
            )
        )
        elements.append(t_ports)
        elements.append(Spacer(1, 12))

    results = data.get("results", {})
    for scanner_name, scanner_data in results.items():
        elements.append(Paragraph(scanner_name, HEADING2))
        elements.append(Spacer(1, 6))

        if isinstance(scanner_data, dict):
            list_tables = []
            kv_plain = {}
            for k, v in scanner_data.items():
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    tbls = table_from_list_of_dicts(v)
                    list_tables.append((k, tbls))
                elif isinstance(v, list) and v:
                    kv_plain[k] = v
                elif isinstance(v, dict):
                    kv_plain[k] = v
                else:
                    kv_plain[k] = v

            if kv_plain:
                elements.append(table_from_kv(kv_plain, col_widths=(60 * mm, None)))
                elements.append(Spacer(1, 8))

            for title, tbls in list_tables:
                elements.append(Paragraph(str(title), HEADING3))
                elements.append(Spacer(1, 4))
                for tbl in tbls:
                    elements.append(tbl)
                    elements.append(Spacer(1, 8))

        elif isinstance(scanner_data, list):
            tbls = table_from_list_of_dicts(scanner_data)
            for tbl in tbls:
                elements.append(tbl)
                elements.append(Spacer(1, 8))
        else:
            elements.append(Paragraph(str(scanner_data), NORMAL))
            elements.append(Spacer(1, 6))

        elements.append(Spacer(1, 10))

    doc.build(elements)
    print(f"[+] Report saved to {output_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python report.py input.json [output.pdf]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = "scan_report.pdf" if len(sys.argv) < 3 else sys.argv[2]

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    generate_report(data, output_file)


if __name__ == "__main__":
    main()
