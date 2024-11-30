import React from 'react';
import { Link } from 'react-router-dom';
import './Home.css';

const Home = () => {
    return (
        <div className="home-container">
            <h1>Welcome to ScanQuill</h1>
            <div className="home-buttons">
                <Link to="/pdfscan">
                    <button>PDF Scan</button>
                </Link>
                <Link to="/messageanalysis">
                    <button>Message Analysis</button>
                </Link>
            </div>

            <div className="info-containers">
                <div className="info-box threat-info">
                    <h3>PDF Threats</h3>
                    <p>
                        PDFs can contain malicious JavaScript, embedded files, and exploits. Be cautious
                        of unknown or unexpected files, especially those with macros or executable
                        content.
                    </p>
                </div>
                <div className="info-box phishing-warning">
                    <h3>Phishing Warnings</h3>
                    <p>
                        Phishing messages often aim to steal sensitive data. Look out for suspicious
                        links, urgent requests, and requests for personal or financial information.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Home;
