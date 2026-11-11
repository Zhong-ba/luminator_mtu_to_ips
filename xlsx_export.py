"""Minimal .xlsx writer (standard library only) for tabular exports.

Writes worksheets of text and integer cells with a bold, frozen header row,
an auto-filter and sized columns.  Text uses inline strings, which Excel,
LibreOffice and Google Sheets all read.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

_INVALID_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _column_letter(index: int) -> str:
    letters = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _cell(ref: str, value, style: int = 0) -> str:
    style_attr = f' s="{style}"' if style else ""
    if isinstance(value, bool) or value is None:
        value = "" if value is None else str(value)
    if isinstance(value, int):
        return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
    text = escape(_INVALID_XML.sub("", str(value)))
    space = ' xml:space="preserve"' if text != text.strip() else ""
    return f'<c r="{ref}"{style_attr} t="inlineStr"><is><t{space}>{text}</t></is></c>'


def _sheet_xml(headers: list[str], rows: list[list]) -> str:
    widths = [len(str(header)) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], max((len(part) for part in str(value).split("\n")), default=0))
    columns = "".join(
        f'<col min="{i + 1}" max="{i + 1}" width="{min(max(width + 2, 8), 80)}" customWidth="1"/>'
        for i, width in enumerate(widths))
    lines = ['<row r="1">' + "".join(_cell(f"{_column_letter(i)}1", header, 1)
                                     for i, header in enumerate(headers)) + "</row>"]
    for r, row in enumerate(rows, start=2):
        lines.append(f'<row r="{r}">' + "".join(_cell(f"{_column_letter(i)}{r}", value)
                                                for i, value in enumerate(row)) + "</row>")
    last = f"{_column_letter(len(headers) - 1)}{len(rows) + 1}"
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
        'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        f"<cols>{columns}</cols><sheetData>{''.join(lines)}</sheetData>"
        f'<autoFilter ref="A1:{last}"/></worksheet>')


def write_xlsx_sheets(path, sheets: list[tuple[str, list[str], list[list]]]) -> None:
    """Write several worksheets, each given as (name, headers, rows)."""
    names = []
    for name, _, _ in sheets:
        clean = re.sub(r"[\[\]:*?/\\]", "_", name)[:31] or f"Sheet{len(names) + 1}"
        while clean.lower() in (n.lower() for n in names):
            clean = clean[:28] + f"_{len(names) + 1}"
        names.append(clean)
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for i in range(1, len(sheets) + 1))
    sheet_entries = "".join(f'<sheet name="{escape(name)}" sheetId="{i}" r:id="rId{i}"/>'
                            for i, name in enumerate(names, start=1))
    filters = "".join(
        f'<definedName name="_xlnm._FilterDatabase" localSheetId="{i}" hidden="1">'
        f"'{escape(name)}'!$A$1:${_column_letter(len(headers) - 1)}${len(rows) + 1}</definedName>"
        for i, (name, (_, headers, rows)) in enumerate(zip(names, sheets)))
    relationships = "".join(
        f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1))
    files = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            f"{overrides}"
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            "</Types>"),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>"),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f"<sheets>{sheet_entries}</sheets><definedNames>{filters}</definedNames></workbook>"),
        "xl/_rels/workbook.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{relationships}"
            f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            "</Relationships>"),
        "xl/styles.xml": (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
            '<fills count="2"><fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="gray125"/></fill></fills>'
            '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
            "</styleSheet>"),
    }
    for i, (_, headers, rows) in enumerate(sheets, start=1):
        files[f"xl/worksheets/sheet{i}.xml"] = _sheet_xml(headers, rows)
    with zipfile.ZipFile(Path(path), "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content.encode("utf-8"))


def write_xlsx(path, headers: list[str], rows: list[list], sheet_name: str = "Sheet1") -> None:
    write_xlsx_sheets(path, [(sheet_name, headers, rows)])
