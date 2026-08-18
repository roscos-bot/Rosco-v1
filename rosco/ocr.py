"""Local OCR — reads scanned PDFs and image files with Tesseract, fully offline.

A text-based PDF is read by pypdf (google._pdf_text); this is the fallback for the
ones with NO embedded text (a scan, a photo of a page) and for image files. Scanned
PDF pages are rasterized with PyMuPDF, then handed to Tesseract; images go straight
to Tesseract. No cloud, no per-page model spend.

Needs the tesseract binary (winget UB-Mannheim.TesseractOCR) + pytesseract + PyMuPDF
+ Pillow. If any is missing OR tesseract can't be located, every call returns '' so a
pull just degrades that file to 'unreadable' — it never crashes the pull. Page-capped
so a large scan set can't hang a synchronous pull.
"""
from __future__ import annotations

_READY = False          # have we resolved tesseract yet?
_TESS = None            # the configured pytesseract module, or None


def _tess():
    """The configured pytesseract module, or None if OCR isn't available. Locates
    the binary via PATH then the usual Windows install dirs, and probes that it
    actually runs before trusting it."""
    global _READY, _TESS
    if _READY:
        return _TESS
    _READY = True
    try:
        import os
        import shutil

        import pytesseract
        cmd = shutil.which("tesseract")
        if not cmd:
            for p in (r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                      r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                      os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe")):
                if os.path.exists(p):
                    cmd = p
                    break
        if cmd:
            pytesseract.pytesseract.tesseract_cmd = cmd
        pytesseract.get_tesseract_version()      # fails loudly here if the binary is missing/broken
        _TESS = pytesseract
    except Exception:
        _TESS = None
    return _TESS


def available() -> bool:
    return _tess() is not None


def image_text(data: bytes) -> str:
    """OCR one image (bytes). '' if OCR isn't set up or nothing is found."""
    t = _tess()
    if not t:
        return ""
    try:
        import io

        from PIL import Image
        im = Image.open(io.BytesIO(data))
        im.load()
        return (t.image_to_string(im) or "").strip()
    except Exception:
        return ""


def pdf_ocr_text(data: bytes, max_pages: int = 15, dpi: int = 200) -> str:
    """OCR a scanned PDF: rasterize each page (PyMuPDF) and read it. Page-capped so a
    big scan set can't hang the pull. '' if OCR / render isn't available."""
    t = _tess()
    if not t:
        return ""
    try:
        import io

        import pymupdf
        from PIL import Image
        doc = pymupdf.open(stream=data, filetype="pdf")
        zoom = dpi / 72.0
        mat = pymupdf.Matrix(zoom, zoom)
        out = []
        for i, page in enumerate(doc):
            if i >= max_pages:
                break
            pix = page.get_pixmap(matrix=mat)
            im = Image.open(io.BytesIO(pix.tobytes("png")))
            out.append((t.image_to_string(im) or "").strip())
        doc.close()
        return "\n".join(p for p in out if p).strip()
    except Exception:
        return ""
