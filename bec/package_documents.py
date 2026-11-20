"""Small, dependency-free XLSX and PDF documents with inert text and internal links."""
import io
import re
import zipfile
from dataclasses import dataclass
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


def _pdf_display(text):
    """Use reversible code-point labels for characters absent from WinAnsi."""
    result = []
    for char in display_text(text):
        try:
            char.encode("cp1252")
        except UnicodeEncodeError:
            result.append(f"[U+{ord(char):04X}]")
        else:
            result.append(char)
    return "".join(result)


def _pdf_text(text):
    raw = _pdf_display(text).encode("cp1252")
    return b"(" + b"".join(b"\\" + bytes([ch]) if ch in b"\\()" else
                              f"\\{ch:03o}".encode() if ch < 32 or ch >= 127 else bytes([ch]) for ch in raw) + b")"


@dataclass(frozen=True)
class PdfParagraph:
    """Display text with explicit generated reference targets, never source URLs."""
    text: str
    style: str = "body"
    links: tuple[str, ...] = ()
    keep_with_next: bool = False


@dataclass(frozen=True)
class PdfSection:
    heading: str
    paragraphs: tuple
    page_break: bool = False


def _text_width(text, size):
    """Conservative Helvetica/Helvetica-Bold width bound, in points.

    The bound is deliberately shared by both fonts. Extended WinAnsi characters
    get a full em; long unbroken names therefore wrap without a font dependency.
    """
    total = 0
    for char in _pdf_display(text):
        if char in " ilI.,:;!'|`":
            total += 300
        elif char in "ftr()[]{}":
            total += 450
        elif char in "mwMW@%&":
            total += 1000
        elif "A" <= char <= "Z":
            total += 800
        elif "a" <= char <= "z":
            total += 650
        elif ord(char) < 127:
            total += 650
        else:
            total += 1000
    return total * size / 1000


def _wrap_pdf(text, size, width=524):
    words = _pdf_display(text).split()
    lines, line = [], ""
    for word in words:
        if line and _text_width(line + " " + word, size) <= width:
            line += " " + word
            continue
        if line:
            lines.append(line)
            line = ""
        for char in word:
            if line and _text_width(line + char, size) > width:
                lines.append(line)
                line = ""
            line += char
    return [*lines, line] if line else lines or [""]


def write_pdf(path, title, sections, references, *,
              subtitle="Read-only evidence package. See manifest.json for hashes and source limits.",
              reference_heading="Evidence reference index"):
    """Write an inert PDF with section bookmarks and internal evidence links.

    Existing (heading, paragraphs) section pairs remain supported. PdfSection can
    start a page; PdfParagraph adds a subheading, note, or explicit evidence links.
    Ordinary strings stay literal. references contains generated (ID, text) pairs;
    reference_heading=None suppresses the index for a run-level navigation report.
    Unsupported font characters appear as [U+XXXX]. Unicode originals remain in
    the UTF-8 CSVs, workbook and original evidence.
    """
    styles = {"title": (22, 28, True), "heading": (15, 20, True),
              "subheading": (11, 15, True), "body": (10.5, 14.5, False),
              "note": (9, 12.5, False)}
    blocks, bookmarks = [], []

    def paragraph(value, *, style="body", anchor=None):
        value = value if isinstance(value, PdfParagraph) else PdfParagraph(str(value), style)
        if value.style not in styles:
            raise CaseError("Unknown PDF paragraph style.")
        size, leading, bold = styles[value.style]
        lines = _wrap_pdf(value.text, size)
        return [(text, size, leading, bold, anchor if index == 0 else None, value.links)
                for index, text in enumerate(lines)]

    blocks.append((paragraph(title, style="title"), False, 0))
    if subtitle:
        blocks.append((paragraph(subtitle, style="note"), False, 3))
    for index, section in enumerate(sections):
        if not isinstance(section, PdfSection):
            section = PdfSection(section[0], tuple(section[1]))
        anchor = f"section-{index}"
        bookmarks.append((section.heading, anchor))
        head = paragraph(section.heading, style="heading", anchor=anchor)
        items = list(section.paragraphs)
        # Keep a section title with its first paragraph; a subheading with its body.
        if items:
            head += paragraph(items.pop(0))
        blocks.append((head, section.page_break, 14))
        while items:
            item = items.pop(0)
            block = paragraph(item)
            while isinstance(item, PdfParagraph) and (item.keep_with_next or item.style == "subheading") and items:
                item = items.pop(0)
                block += paragraph(item)
            blocks.append((block, False, 7))
    if reference_heading is not None:
        anchor = "reference-index"
        bookmarks.append((reference_heading, anchor))
        heading = paragraph(reference_heading, style="heading", anchor=anchor)
        refs = list(references)
        if not refs:
            heading += paragraph("No record-level evidence references are present in this document.", style="note")
        for index, (identifier, text) in enumerate(refs):
            block = paragraph(f"{identifier} | {display_text(text)}", style="note", anchor=identifier)
            blocks.append(((heading if index == 0 else []) + block, index == 0, 7))
        if not refs:
            blocks.append((heading, False, 14))
    pages, y = [[]], 792.0
    for block, page_break, gap in blocks:
        needed = sum(line[2] for line in block) + gap
        if pages[-1] and (page_break or needed <= 730 and y - needed < 62):
            pages.append([])
            y = 792.0
        if pages[-1]:
            y -= gap
        for line in block:
            if y - line[2] < 62:
                pages.append([])
                y = 792.0
            pages[-1].append((*line, y))
            y -= line[2]
    if len(pages) > 5000:
        raise CaseError("Package PDF exceeds the 5,000-page limit.")
    objects = [None, None, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"]
    page_numbers = [5 + 2 * index for index in range(len(pages))]
    destinations = {anchor: (page_numbers[index], y + size + 5) for index, page in enumerate(pages)
                    for _, size, _, _, anchor, _, y in page if anchor}
    for page_index, page in enumerate(pages):
        commands, annotations = [], []
        for text, size, _, bold, anchor, links, y in page:
            color = b"0.12 0.23 0.32 rg" if bold else b"0.14 0.17 0.20 rg"
            commands.append(color + b" BT /" + (b"F2" if bold else b"F1") + f" {size:g} Tf 44 {y:g} Td ".encode() + _pdf_text(text) + b" Tj ET")
            for identifier in links:
                # Link only an explicitly generated reference paragraph. Source
                # names containing an E-ID remain ordinary unlinked text.
                if identifier in destinations and re.search(r"\b" + re.escape(identifier) + r"\b", text):
                    target, top = destinations[identifier]
                    annotations.append(f"<< /Type /Annot /Subtype /Link /Rect [44 {y - 2:g} 568 {y + size:g}] "
                                       f"/Border [0 0 0] /Dest [{target} 0 R /FitH {top:g}] >>")
                    break  # A reference line has one unambiguous destination.
        commands.append(b"0.75 0.80 0.83 RG 0.5 w 44 50 m 568 50 l S")
        commands.append(b"0.35 0.39 0.42 rg BT /F1 8 Tf 44 32 Td " + _pdf_text(f"Page {page_index + 1} of {len(pages)} | Read-only review copy") + b" Tj ET")
        content = b"\n".join(commands)
        page_number = page_numbers[page_index]
        page_obj = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
                    f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {page_number + 1} 0 R "
                    + ("/Annots [" + " ".join(annotations) + "] " if annotations else "") + ">>")
        objects.extend([page_obj.encode(), b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream"])
    if bookmarks:
        outline = len(objects) + 1
        objects.append(f"<< /Type /Outlines /First {outline + 1} 0 R /Last {outline + len(bookmarks)} 0 R /Count {len(bookmarks)} >>".encode())
        for index, (heading, anchor) in enumerate(bookmarks, 1):
            target, top = destinations[anchor]
            siblings = (f" /Prev {outline + index - 1} 0 R" if index > 1 else "") + (f" /Next {outline + index + 1} 0 R" if index < len(bookmarks) else "")
            objects.append(b"<< /Title " + _pdf_text(heading) + f" /Parent {outline} 0 R /Dest [{target} 0 R /FitH {top:g}]{siblings} >>".encode())
        objects[0] = f"<< /Type /Catalog /Pages 2 0 R /Outlines {outline} 0 R >>".encode()
    else:
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
