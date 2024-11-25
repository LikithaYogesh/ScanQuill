#!/usr/bin/env python3

import argparse
import os
import subprocess
import yara
import PyPDF2

# YARA rule for basic PDF threats
YARA_RULES = r"""
rule SuspiciousPDF {
    meta:
        description = "Detects suspicious PDFs with JavaScript or embedded files"
    strings:
        $javascript = /\/JavaScript|\/JS/
        $embedded = /\/EmbeddedFile/
    condition:
        $javascript or $embedded
}
"""

def scan_pdf_with_yara(file_path):
    rules = yara.compile(source=YARA_RULES)
    with open(file_path, "rb") as file:
        matches = rules.match(data=file.read())
    return matches

def analyze_with_pdfid(file_path):
    try:
        result = subprocess.run(
            ["python3", "pdfid.py", file_path],
            capture_output=True,
            text=True
        )
        return result.stdout if result.returncode == 0 else "Error running PDFiD."
    except Exception as e:
        return f"Exception while running PDFiD: {e}"

def scan_pdf(file_path):
    print(f"Scanning: {file_path}")

    try:
        with open(file_path, "rb") as file:
            pdf_reader = PyPDF2.PdfReader(file)
            metadata = pdf_reader.metadata
            num_pages = len(pdf_reader.pages)
    except Exception as e:
        metadata = {"Error": str(e)}
        num_pages = "Unknown"

    pdfid_output = analyze_with_pdfid(file_path)

    yara_matches = scan_pdf_with_yara(file_path)

    print("\n--- Scan Results ---")
    print(f"File: {file_path}")
    print(f"Number of Pages: {num_pages}")
    print("Metadata:")
    for key, value in metadata.items():
        print(f"  {key}: {value}")
    print("\nPDFiD Output:")
    print(pdfid_output)
    print("\nYARA Matches:")
    if yara_matches:
        for match in yara_matches:
            print(f"  Rule: {match.rule}")
    else:
        print("  No suspicious content detected.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PDF Scanner Tool")
    parser.add_argument("file", help="Path to the PDF file to scan")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: File not found: {args.file}")
        exit(1)

    scan_pdf(args.file)
