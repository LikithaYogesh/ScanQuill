# ScanQuill

ScanQuill is a web-based tool designed to enhance digital security by analyzing files and messages for potential cyber threats. It helps users scan PDF documents for vulnerabilities and evaluate text messages for phishing attempts or other suspicious content.

---

## Features

   PDF Scan: Analyzes PDF files for malicious scripts, embedded vulnerabilities, and other threats.
   
   Message Analysis: Detects potential phishing attempts or suspicious elements in text messages.
   
   User-Friendly Interface: A clean and responsive React-based frontend for easy interaction.
   
   AI-Powered Backend: Leverages Google Generative AI for advanced text analysis.
   
   YARA Integration: Utilizes YARA rules for scanning PDFs for embedded risks.

---

## Installation

Backend Setup (Flask)

Clone the repository:

    git clone https://github.com/your-repo/scanquill.git
    cd scanquill

Create a virtual environment:

    python3 -m venv venv
    source venv/bin/activate

Install required Python packages:

    pip install -r requirements.txt

Install YARA (if not already installed):

    sudo apt-get install yara

Start the Flask backend:

    python app.py

Frontend Setup (React)

 avigate to the frontend directory:

    cd frontend

Install dependencies:

    npm install

Start the React development server:

    npm start

---

## Usage

Home Page

   Navigate to the home page at http://localhost:3000.
   Select either PDF Scan or Message Analysis to proceed.

PDF Scan

   Upload a PDF file to scan for vulnerabilities and threats.
   View a detailed report showing metadata, potential risks, and scan results.

Message Analysis

   Enter a text message to analyze.
   Receive a detailed report indicating whether the message contains phishing indicators or suspicious elements.

---

## Technologies Used

### Backend

  Flask (Python)
  
  Google Generative AI
  
  YARA
  
  PyPDF2

### Frontend

  React
  
  React Router DOM
  
  Axios

---

## Contributions

Contributions to ScanQuill are welcome! Please submit a pull request or open an issue to discuss changes.

---

## License

This project is licensed under the MIT License.

---

## Acknowledgments

Didier Stevens for the fantastic PDFiD tool.

---

# Stay safe, and scan with confidence using ScanQuill!
