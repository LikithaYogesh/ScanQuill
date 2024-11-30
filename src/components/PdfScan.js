import React, { useState } from 'react';
import './PdfScan.css';

const PdfScan = () => {
    const [file, setFile] = useState(null);
    const [report, setReport] = useState(null);

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!file) {
            alert("Please select a file first!");
            return;
        }

        const formData = new FormData();
        formData.append('pdf_file', file);

        try {
            const response = await fetch('http://127.0.0.1:5000/upload', {
                method: 'POST',
                body: formData,
            });

            const data = await response.json();
            setReport(data);
        } catch (error) {
            console.error("Error uploading file:", error);
        }
    };

    return (
        <div className="pdfscan-container">
            <h1>PDF Scan</h1>
            <form onSubmit={handleSubmit}>
                <input type="file" onChange={handleFileChange} accept=".pdf" />
                <button type="submit">Scan PDF</button>
            </form>

            {report && (
                <div className="report-container">
                    <h2>Scan Report</h2>

                    <div className="report-section">
                        <h3>File Information</h3>
                        <p><strong>Filename:</strong> {report.filename}</p>
                        <p><strong>Number of Pages:</strong> {report.num_pages}</p>
                    </div>

                    <div className="report-section">
                        <h3>Metadata</h3>
                        {report.metadata ? (
                            <ul>
                                {Object.entries(report.metadata).map(([key, value]) => (
                                    <li key={key}>
                                        <strong>{key}:</strong> {value}
                                    </li>
                                ))}
                            </ul>
                        ) : (
                            <p>No metadata found.</p>
                        )}
                    </div>

                    <div className="report-section">
                        <h3>PDFiD Output</h3>
                        <pre className="pdfid-output">{report.pdfid_output}</pre>
                    </div>

                    <div className="report-section">
                        <h3>YARA Matches</h3>
                        {report.yara_matches.length > 0 ? (
                            <ul>
                                {report.yara_matches.map((match, index) => (
                                    <li key={index}>{match}</li>
                                ))}
                            </ul>
                        ) : (
                            <p>No suspicious patterns detected.</p>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default PdfScan;
