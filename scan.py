import sys
import os
import subprocess
import PyPDF2
import yara

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
        # Adjust the path if pdfid.py is in a specific directory
        result = subprocess.run(
            ["python3", "pdfid.py", file_path],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("[+] PDFiD Output:")
            print(result.stdout)
        else:
            print("[-] Error running PDFiD.")
    except Exception as e:
        print(f"[-] Exception while running PDFiD: {e}")

def scan_pdf(file_path):
    print(f"Scanning: {file_path}")
    
    # Step 1: Check metadata with PyPDF2
    try:
        with open(file_path, "rb") as file:
            pdf_reader = PyPDF2.PdfReader(file)
            print(f"[+] Number of pages: {len(pdf_reader.pages)}")
            metadata = pdf_reader.metadata
            print("[+] Metadata:")
            for key, value in metadata.items():
                print(f"    {key}: {value}")
    except Exception as e:
        print(f"[-] Error reading PDF metadata: {e}")

    # Step 2: Analyze with pdfid
    analyze_with_pdfid(file_path)

    # Step 3: Check for YARA matches
    yara_matches = scan_pdf_with_yara(file_path)
    if yara_matches:
        print("[!] Suspicious content detected by YARA rules:")
        for match in yara_matches:
            print(f"    {match.rule}")
    else:
        print("[+] No suspicious content detected by YARA rules.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_pdf>")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    if not os.path.isfile(pdf_path):
        print(f"[-] File not found: {pdf_path}")
        sys.exit(1)
    
    scan_pdf(pdf_path)
