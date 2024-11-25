# ScanQuill
## Advanced PDF Security Scanner

ScanQuill is a powerful and intuitive tool designed to scan PDF files for malicious content without opening them. By leveraging advanced techniques like YARA rules and PDF object analysis, ScanQuill ensures that your documents are safe from hidden threats.

---

## Features

PDF Metadata Extraction: Extract and display key metadata, such as author, creation date, and number of pages.
PDFiD Integration: Analyze PDF structure for suspicious objects like JavaScript or embedded files.
YARA Rule Scanning: Detect known malicious patterns in PDF files using custom and extensible YARA rules.
User-Friendly CLI: Run the tool easily from the terminal with a single command.
Web Interface: A simple and effective web interface for scanning PDFs through your browser (optional).

---

## Installation

Prerequisites:

  Kali Linux or Any Linux Distribution
  Python 3.8+
  Required Python libraries:
  flask
  PyPDF2
  yara-python
  werkzeug

Install dependencies using:

     pip3 install -r requirements.txt

---

## Install as a CLI Tool

Clone the repository:

    git clone https://github.com/yourusername/scanquill.git
    cd scanquill

Make the script executable:

    chmod +x cli.py

Move it to /usr/local/bin for system-wide access:

    sudo mv cli.py /usr/local/bin/scanquill

Run the tool:

    scanquill <path_to_pdf>

---

## Run the Web Interface

Start the Flask app:

    python3 app.py

Open your browser and navigate to:

    http://127.0.0.1:5000/

Upload a PDF file to scan it via the web interface.

---

## Usage

Command-Line Interface

Run the tool from the terminal:

    scanquill <path_to_pdf>

Example:

    scanquill /home/user/sample.pdf

Output:

    Metadata summary
    Suspicious object analysis (via PDFiD)
    Malicious patterns detected by YARA rules

---

## Contributing

Contributions are welcome! To contribute:

Fork the repository.
Create a new branch for your feature:

    git checkout -b feature-name

Commit and push your changes:

    git commit -m "Added new feature"
    git push origin feature-name

Open a pull request.

---

## License

This project is licensed under the MIT License

---

## Acknowledgments

Didier Stevens for the fantastic PDFiD tool.
Open Source Community for the inspiration and libraries.
