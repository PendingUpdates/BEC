"""Small, dependency-free XLSX and PDF documents with inert text and internal links."""
import io
import re
import textwrap
import zipfile
from xml.sax.saxutils import escape, quoteattr

from .storage import CaseError


def display_text(value, limit=32767):
    """Replace XML/control characters only in display copies; originals stay separate."""
    value = "" if value is None else str(value)
    value = "".join(ch if ch in "\n\t" or 32 <= ord(ch) <= 0xD7FF or 0xE000 <= ord(ch) <= 0xFFFD
                    or 0x10000 <= ord(ch) <= 0x10FFFF else "\ufffd" for ch in value)
    suffix = " [display truncated; see original evidence]"
    return value if len(value) <= limit else value[:limit - len(suffix)] + suffix


def _column(number):
    result = ""
    while number:
        number, remainder = divmod(number - 1, 26)
        result = chr(65 + remainder) + result
    return result


def write_workbook(path, tables, evidence_locations):
    """Write OOXML. Every cell is inline text; hyperlinks target this workbook only.

    tables contains dictionaries with name, columns and rows. evidence_locations
    maps generated evidence IDs to one-based rows in the mandatory Evidence sheet.
    No formulas, external relationships, macros, or source-supplied sheet names.
    """
    names = [table["name"] for table in tables]
    if (len(names) != len(set(names)) or "Evidence" not in names or
            any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,30}", name) for name in names)):
        raise CaseError("Invalid package workbook sheet layout.")
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    relationships = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    parts = {}
    sheets, links, types = [], [], []
    for index, table in enumerate(tables, 1):
        columns, rows = table["columns"], table["rows"]
        if not 1 <= len(columns) <= 128 or len(rows) > 1_000_000:
            raise CaseError("Package workbook exceeds bounded sheet dimensions.")
        last = _column(len(columns))
        body, hyperlinks = [], []
        for row_number, values in enumerate([columns, *rows], 1):
            if len(values) != len(columns):
                raise CaseError("Package workbook row width differs from its columns.")
            cells = []
            for column, value in enumerate(values, 1):
                location = f"{_column(column)}{row_number}"
                text = display_text(value)
                cells.append(f'<c r="{location}" s="{1 if row_number == 1 else 0}" t="inlineStr">'
                             f'<is><t xml:space="preserve">{escape(text)}</t></is></c>')
                if (row_number > 1 and column - 1 in table.get("evidence_columns", ()) and
                        table["name"] != "Evidence" and text in evidence_locations):
                    target = f"'Evidence'!A{evidence_locations[text]}"
                    hyperlinks.append(f'<hyperlink ref="{location}" location={quoteattr(target)} display={quoteattr(text)}/>')
            body.append(f'<row r="{row_number}">' + "".join(cells) + '</row>')
        cols = ''.join(f'<col min="{column}" max="{column}" width="{22 if column == 1 else 36}" customWidth="1"/>'
                       for column in range(1, len(columns) + 1))
        worksheet = (f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="{ns}">'
                     f'<dimension ref="A1:{last}{len(rows) + 1}"/>'
                     '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
                     'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
                     f'<cols>{cols}</cols><sheetData>{"".join(body)}</sheetData>'
                     f'<autoFilter ref="A1:{last}{len(rows) + 1}"/>'
                     + (f'<hyperlinks>{"".join(hyperlinks)}</hyperlinks>' if hyperlinks else '') + '</worksheet>')
        parts[f"xl/worksheets/sheet{index}.xml"] = worksheet
        sheets.append(f'<sheet name={quoteattr(table["name"])} sheetId="{index}" r:id="rId{index}"/>')
        links.append(f'<Relationship Id="rId{index}" Type="{relationships}/worksheet" Target="worksheets/sheet{index}.xml"/>')
        types.append(f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
                     'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    parts["xl/workbook.xml"] = (f'<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="{ns}" xmlns:r="{relationships}">'
                                '<bookViews><workbookView/></bookViews><sheets>' + ''.join(sheets) + '</sheets></workbook>')
    links.append(f'<Relationship Id="rId{len(tables) + 1}" Type="{relationships}/styles" Target="styles.xml"/>')
    parts["xl/_rels/workbook.xml.rels"] = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + ''.join(links) + '</Relationships>')
    parts["_rels/.rels"] = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="{relationships}/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    parts["xl/styles.xml"] = (f'<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="{ns}">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1">'
        '<alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" '
        'applyFont="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')
    parts["[Content_Types].xml"] = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        + ''.join(types) + '</Types>')
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, text in sorted(parts.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, text.encode("utf-8"))
    with path.open("xb") as stream:
        stream.write(buffer.getvalue())


def _pdf_text(text):
    raw = display_text(text).encode("cp1252", errors="replace")
    return b"(" + b"".join(b"\\" + bytes([ch]) if ch in b"\\()" else
                              f"\\{ch:03o}".encode() if ch < 32 or ch >= 127 else bytes([ch]) for ch in raw) + b")"


def write_pdf(path, title, sections, references):
    """Write a real paginated PDF; reference links are /Dest page destinations only.

    sections is (heading, text-lines) pairs. references is (generated ID, text)
    pairs. The standard-font display substitutes unsupported characters; exact
    Unicode text remains in the UTF-8 CSVs, workbook and original evidence.
    """
    def wrap(text):
        return textwrap.wrap(display_text(text), 55, replace_whitespace=True,
                             break_long_words=True, break_on_hyphens=False) or [""]

    blocks = [[(title, True, None)], [(line, False, None) for line in wrap(
        "Read-only evidence package. See manifest.json for hashes and source limits.")]]
    for heading, paragraphs in sections:
        block = [("", False, None), (heading, True, None)]
        if paragraphs:
            block.extend((line, False, None) for line in wrap(paragraphs[0]))
        blocks.append(block)
        blocks.extend([(line, False, None) for line in wrap(paragraph)] for paragraph in paragraphs[1:])
    index_header = [("", False, None), ("Evidence reference index", True, None)]
    for identifier, text in references:
        block = [(line, False, identifier if index == 0 else None)
                 for index, line in enumerate(wrap(f"{identifier} | {display_text(text)}"))]
        blocks.append(index_header + block)
        index_header = []
    if index_header:
        blocks.append(index_header)
    per_page = 48
    pages = [[]]
    for block in blocks:
        if len(block) <= per_page and pages[-1] and len(pages[-1]) + len(block) > per_page:
            pages.append([])
        for line in block:
            if len(pages[-1]) >= per_page:
                pages.append([])
            pages[-1].append(line)
    if len(pages) > 5000:
        raise CaseError("Package PDF exceeds the 5,000-page limit.")
    objects = [None, None, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"]
    page_numbers = [5 + 2 * index for index in range(len(pages))]
    destinations = {}
    for page_index, page in enumerate(pages):
        for line_index, (_, _, identifier) in enumerate(page):
            if identifier:
                destinations[identifier] = (page_numbers[page_index], 790 - 14 * line_index)
    for page_index, page in enumerate(pages):
        commands, annotations = [], []
        for line_index, (text, bold, anchor) in enumerate(page):
            y = 790 - 14 * line_index
            commands.append(b"BT /" + (b"F2" if bold else b"F1") + b" 9 Tf 44 " + str(y).encode() + b" Td " + _pdf_text(text) + b" Tj ET")
            if not anchor:
                for identifier in re.findall(r"\bE[0-9]{6}\b", text):
                    if identifier in destinations:
                        target, top = destinations[identifier]
                        annotations.append(f"<< /Type /Annot /Subtype /Link /Rect [44 {y - 2} 566 {y + 10}] "
                                           f"/Border [0 0 0] /Dest [{target} 0 R /FitH {top}] >>")
                        break  # One unambiguous internal target per rendered line.
        commands.append(b"BT /F1 9 Tf 44 32 Td " + _pdf_text(f"Page {page_index + 1} of {len(pages)} | Unicode originals retained separately") + b" Tj ET")
        content = b"\n".join(commands)
        page_number = page_numbers[page_index]
        page_obj = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
                    f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {page_number + 1} 0 R "
                    + ("/Annots [" + " ".join(annotations) + "] " if annotations else "") + ">>")
        objects.extend([page_obj.encode(), b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream"])
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[1] = (f"<< /Type /Pages /Count {len(pages)} /Kids [" + " ".join(f"{number} 0 R" for number in page_numbers) + "] >>").encode()
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(out.tell())
        out.write(str(number).encode() + b" 0 obj\n" + obj + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        out.write(f"{offset:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    with path.open("xb") as stream:
        stream.write(out.getvalue())
