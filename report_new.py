#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report.py
تحويل نتائج JSON من pipeline لملف PDF احترافي بجداول منظمة + غلاف محسّن (SVG) + فوتر ورقم صفحة.
Usage:
    python report.py input1.json [input2.json ...] output.pdf [--logo logo.svg]
"""

import json
import sys
import argparse
from typing import Any, Dict, List, Set, Tuple
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Flowable
)
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import KeepTogether
from reportlab.platypus import KeepTogether, Spacer, Paragraph
from reportlab.lib.enums import TA_CENTER

# ---------- لإدراج SVG ----------
from svglib.svglib import svg2rlg
from reportlab.graphics import renderPDF

class SVGImage(Flowable):
    """Wrapper to insert SVG with reportlab, centered horizontally."""
    def __init__(self, svg_path: str, max_width: float = None, max_height: float = None):
        super().__init__()
        self.svg_path = svg_path
        self.max_width = max_width
        self.max_height = max_height
        self.drawing = svg2rlg(svg_path)
        # scale to fit max width/height
        if max_width or max_height:
            sx = max_width / self.drawing.width if max_width else 1
            sy = max_height / self.drawing.height if max_height else 1
            scale = min(sx, sy)
            self.drawing.width *= scale
            self.drawing.height *= scale
            for elem in self.drawing.contents:
                elem.scale(scale, scale)

    def wrap(self, availWidth, availHeight):
        return self.drawing.width, self.drawing.height

    def draw(self):
        # نحسب المسافة بحيث يبقى في النص
        x_offset = (AVAILABLE_WIDTH - self.drawing.width) / 4
        renderPDF.draw(self.drawing, self.canv, x_offset, 0)

# ---------- إعداد ستايلات ----------
BASE_STYLES = getSampleStyleSheet()
NORMAL = BASE_STYLES["Normal"]

TITLE_STYLE = ParagraphStyle(
    "TitleBig", parent=BASE_STYLES["Title"],
    fontName="Helvetica-Bold", fontSize=28, leading=34, textColor=colors.HexColor("#0D47A1"),
    alignment=1
)
SUBTITLE_STYLE = ParagraphStyle(
    "Subtitle", parent=NORMAL, fontName="Helvetica", fontSize=14, leading=18,
    textColor=colors.HexColor("#333333"), alignment=1
)
REPORT_TITLE = ParagraphStyle(
    "ReportTitle", parent=NORMAL, fontName="Helvetica-Bold",
    fontSize=18, leading=22, textColor=colors.HexColor("#0D47A1")
)
SECTION_TITLE = ParagraphStyle(
    "SectionTitle", parent=NORMAL, fontName="Helvetica-Bold",
    fontSize=14, leading=18, textColor=colors.HexColor("#800020")
)
SUBSECTION = ParagraphStyle(
    "SubSection", parent=NORMAL, fontName="Helvetica-Bold",
    fontSize=11, leading=14, textColor=colors.HexColor("#2e5599")
)
CELL_P = ParagraphStyle(
    "cell", parent=NORMAL, fontName="Helvetica", fontSize=9, leading=11
)
SMALL_P = ParagraphStyle(
    "small", parent=NORMAL, fontName="Helvetica", fontSize=8, leading=10
)
FOOTER_P = ParagraphStyle(
    "footer", parent=NORMAL, fontSize=8, alignment=1, textColor=colors.grey
)

# ---------- إعداد ثابتات ----------
PAGE_WIDTH, PAGE_HEIGHT = A4
LEFT_MARGIN = RIGHT_MARGIN = TOP_MARGIN = BOTTOM_MARGIN = 18 * mm
AVAILABLE_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN

MAX_CELL_CHARS = 300
LIST_PREVIEW_ITEMS = 5

# ---------- مساعدة ----------
def safe_text_for_cell(v: Any) -> str:
    if v is None:
        return "N/A"
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        if all(not isinstance(x, (dict, list)) for x in v):
            preview = ", ".join(map(str, v[:LIST_PREVIEW_ITEMS]))
            if len(v) > LIST_PREVIEW_ITEMS:
                preview += f", ... ({len(v)} items)"
            return preview if preview else "[]"
        return f"list({len(v)})"
    if isinstance(v, dict):
        pairs = []
        for i, (k2, v2) in enumerate(v.items()):
            if i >= 6:
                pairs.append("...")
                break
            pairs.append(f"{k2}:{str(v2) if not isinstance(v2, (dict, list)) else type(v2).__name__}")
        return "{" + ", ".join(pairs) + "}"
    return str(v).replace("\r\n", "\n").replace("\r", "\n")

# ---------- إنشاء جدول Key/Value ----------
def table_from_kv(d: Dict[str, Any], prefix: str = None, col_widths=(60 * mm, None)) -> Table:
    rows = [["Key", "Value"]]
    for k, v in d.items():
        if isinstance(v, str) and len(v) > MAX_CELL_CHARS:
            preview = v[:MAX_CELL_CHARS//2].replace("\n", " ") + " ... "
            rows.append([Paragraph(str(k), CELL_P), Paragraph(preview, CELL_P)])
        else:
            rows.append([Paragraph(str(k), CELL_P), Paragraph(safe_text_for_cell(v).replace("\n", "<br/>"), CELL_P)])
    t = Table(rows, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#800020")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
    ]))
    return t

# ---------- إنشاء جدول من list of dicts ----------
def table_from_list_of_dicts(list_of_dicts: List[Dict[str, Any]], prefix: str = None, max_cols_per_table: int = 6) -> List[Table]:
    if not list_of_dicts:
        return [Table([["(empty)"]])]
    keys: List[str] = []
    keyset: Set[str] = set()
    for item in list_of_dicts:
        if isinstance(item, dict):
            for k in item.keys():
                if k not in keyset:
                    keys.append(k)
                    keyset.add(k)
    if not keys:
        rows = [["Value"]]
        for i, item in enumerate(list_of_dicts):
            rows.append([Paragraph(safe_text_for_cell(item).replace("\n", "<br/>"), SMALL_P)])
        t = Table(rows, colWidths=[AVAILABLE_WIDTH], hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e5599")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]))
        return [t]
    tables: List[Table] = []
    for i in range(0, len(keys), max_cols_per_table):
        chunk = keys[i:i+max_cols_per_table]
        header = [Paragraph(str(k), CELL_P) for k in chunk]
        rows = [header]
        for item in list_of_dicts:
            row = []
            for k in chunk:
                v = item.get(k, "N/A") if isinstance(item, dict) else "N/A"
                if isinstance(v, str) and len(v) > MAX_CELL_CHARS:
                    preview = v[:MAX_CELL_CHARS//2].replace("\n", " ") + " ... "
                    row.append(Paragraph(preview, SMALL_P))
                else:
                    row.append(Paragraph(safe_text_for_cell(v).replace("\n", "<br/>"), SMALL_P))
            rows.append(row)
        col_widths = [max(25*mm, AVAILABLE_WIDTH/len(chunk)) for _ in chunk]
        t = Table(rows, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e5599")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ]))
        tables.append(t)
    return tables

# ---------- غلاف خرافي ----------
def add_cover(elements: List, logo_path: str = None):
    cover_content = []

    # اللوغو
    if logo_path:
        try:
            svg_img = SVGImage(logo_path, max_width=140*mm, max_height=80*mm)
            cover_content.append(svg_img)
            cover_content.append(Spacer(1, 24))
        except Exception as e:
            print(f"[!] Logo load failed ({logo_path}): {e} -- continuing without logo")

    # العنوان الكبير
    title_style = TITLE_STYLE.clone('title_center')
    title_style.alignment = TA_CENTER
    cover_content.append(Paragraph("Network Security Scan Report", title_style))
    cover_content.append(Spacer(1, 12))

    # العنوان الفرعي
    subtitle_style = SUBTITLE_STYLE.clone('subtitle_center')
    subtitle_style.alignment = TA_CENTER
    cover_content.append(Paragraph("Comprehensive Security Assessment", subtitle_style))
    cover_content.append(Spacer(1, 12))

    # التاريخ
    cover_content.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    cover_content.append(Spacer(1, 20))

    # الفوتر
    footer_style = FOOTER_P.clone('footer_center')
    footer_style.alignment = TA_CENTER
    cover_content.append(Paragraph("Report generated by VulnEye Security Assessment Framework", footer_style))

    # نحسب المسافة من أعلى الصفحة لتوسيط كل الغلاف
    total_height = sum([c.wrap(AVAILABLE_WIDTH, PAGE_HEIGHT)[1] for c in cover_content])
    top_space = (PAGE_HEIGHT - total_height) / 2
    elements.append(Spacer(1, top_space))

    # نضيف الغلاف كله في كتلة واحدة
    elements.append(KeepTogether(cover_content))
    elements.append(PageBreak())

# ---------- باقي الكود كما هو (add_single_report، add_page_number_and_footer، generate_report، CLI) ----------
# لاحقًا يمكن استخدام نفس دوال add_single_report و generate_report بدون تعديل

# ---------- تقرير مفرد ----------
def add_single_report(data: Dict[str, Any], elements: List, add_pagebreak: bool = False):
    if add_pagebreak:
        elements.append(PageBreak())
    target = data.get("target", "-")
    duration = data.get("duration_seconds", "-")
    elements.append(Paragraph(f"Scan Report for {target}", REPORT_TITLE))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"<b>Target:</b> {target} &nbsp;&nbsp; <b>Scan Duration:</b> {duration} seconds", NORMAL))
    elements.append(Spacer(1, 10))
    # Open ports summary
    open_ports = data.get("open_ports", [])
    if open_ports:
        elements.append(Paragraph("Open Ports Summary", SECTION_TITLE))
        port_rows = [["Port", "Status", "Service (if known)"]]
        port_service_map = {}
        ps = data.get("results", {}).get("Port Scanner", {})
        if isinstance(ps, dict):
            for item in ps.get("open_ports", []) if isinstance(ps.get("open_ports", []), list) else []:
                if isinstance(item, dict) and "port" in item:
                    port_service_map[item.get("port")] = item.get("service", "-")
        for p in open_ports:
            svc = port_service_map.get(p, "-")
            port_rows.append([Paragraph(str(p), CELL_P), Paragraph("Open", CELL_P), Paragraph(str(svc), CELL_P)])
        t_ports = Table(port_rows, colWidths=[30 * mm, 30 * mm, AVAILABLE_WIDTH - 60 * mm], hAlign="LEFT", repeatRows=1)
        t_ports.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#800020")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]))
        elements.append(t_ports)
        elements.append(Spacer(1, 10))
    results = data.get("results", {})
    for scanner_name, scanner_data in results.items():
        elements.append(Paragraph(scanner_name, SUBSECTION))
        elements.append(Spacer(1, 6))
        if isinstance(scanner_data, dict):
            kv_plain = {}
            list_tables = []
            for k, v in scanner_data.items():
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    tbls = table_from_list_of_dicts(v, prefix=f"{scanner_name}.{k}")
                    list_tables.append((k, tbls))
                else:
                    kv_plain[k] = v
            if kv_plain:
                t_kv = table_from_kv(kv_plain, prefix=scanner_name, col_widths=(60*mm, AVAILABLE_WIDTH-60*mm))
                elements.append(t_kv)
                elements.append(Spacer(1, 8))
            for title, tbls in list_tables:
                elements.append(Paragraph(str(title), ParagraphStyle("ltitle", parent=SMALL_P, fontName="Helvetica-Bold", textColor=colors.HexColor("#2e5599"))))
                elements.append(Spacer(1, 4))
                for tbl in tbls:
                    elements.append(tbl)
                    elements.append(Spacer(1, 8))
        elif isinstance(scanner_data, list):
            tbls = table_from_list_of_dicts(scanner_data, prefix=scanner_name)
            for tbl in tbls:
                elements.append(tbl)
                elements.append(Spacer(1, 8))
        else:
            elements.append(Paragraph(safe_text_for_cell(scanner_data).replace("\n", "<br/>"), CELL_P))
            elements.append(Spacer(1, 6))
        elements.append(Spacer(1, 10))

# ---------- فوتر ورقم صفحة ----------
def add_page_number_and_footer(canvas_obj: canvas.Canvas, doc):
    canvas_obj.saveState()
    page_num_text = f"Page {doc.page}"
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawRightString(PAGE_WIDTH - RIGHT_MARGIN, BOTTOM_MARGIN/2, page_num_text)
    footer_text = "Report generated by VulnEye Security Assessment Framework | Confidential"
    canvas_obj.setFont("Helvetica-Oblique", 7)
    canvas_obj.setFillColor(colors.grey)
    canvas_obj.drawCentredString(PAGE_WIDTH/2, BOTTOM_MARGIN/2, footer_text)
    canvas_obj.restoreState()

# ---------- توليد التقرير ----------
def generate_report(list_of_data: List[Dict[str, Any]], output_file: str = "scan_report.pdf", logo_path: str = None):
    doc = BaseDocTemplate(output_file, pagesize=A4,
                          rightMargin=RIGHT_MARGIN, leftMargin=LEFT_MARGIN,
                          topMargin=TOP_MARGIN, bottomMargin=BOTTOM_MARGIN)
    frame = Frame(LEFT_MARGIN, BOTTOM_MARGIN, AVAILABLE_WIDTH, PAGE_HEIGHT-TOP_MARGIN-BOTTOM_MARGIN, id='normal')
    template = PageTemplate(id='template', frames=[frame], onPage=add_page_number_and_footer)
    doc.addPageTemplates([template])

    elements: List[Any] = []
    add_cover(elements, logo_path)
    for idx, data in enumerate(list_of_data):
        add_single_report(data, elements, add_pagebreak=(idx > 0))

    doc.build(elements)
    print(f"[+] Report saved to {output_file}")

# ---------- CLI ----------
def parse_cli():
    parser = argparse.ArgumentParser(description="Generate PDF report(s) from pipeline JSON outputs.")
    parser.add_argument("paths", nargs="+", help="input JSON files followed by output PDF (last path must be .pdf)")
    parser.add_argument("--logo", help="optional logo path (SVG)", default=None)
    args = parser.parse_args()

    if len(args.paths) < 2:
        parser.error("Provide at least one input JSON and one output PDF path.")
    output = args.paths[-1]
    if not output.lower().endswith(".pdf"):
        parser.error("Last path must be the output PDF file (ending with .pdf)")
    inputs = args.paths[:-1]
    return inputs, output, args.logo

def main():
    input_files, output_file, logo_path = parse_cli()
    list_of_data = []
    for path in input_files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                list_of_data.append(json.load(f))
        except Exception as e:
            print(f"[!] Failed to load {path}: {e}")
    if not list_of_data:
        print("[!] No valid input JSON loaded. Exiting.")
        sys.exit(1)
    generate_report(list_of_data, output_file, logo_path=logo_path)

if __name__ == "__main__":
    main()
