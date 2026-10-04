from pathlib import Path
from pypdf import PdfReader
from docx import Document

ALLOWED = {".txt", ".pdf", ".docx"}

def extract_text(file_storage):
    filename = file_storage.filename or ""
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED:
        raise ValueError("Only TXT, PDF and DOCX files are supported.")
    if suffix == ".txt":
        return file_storage.read().decode("utf-8", errors="replace")
    if suffix == ".pdf":
        reader = PdfReader(file_storage.stream)
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    document = Document(file_storage.stream)
    return "\n".join(p.text for p in document.paragraphs)
