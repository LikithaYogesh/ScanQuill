import React, { useState } from 'react';
import './MessageAnalysis.css';

const MessageAnalysis = () => {
    const [message, setMessage] = useState('');
    const [analysis, setAnalysis] = useState(null);

    const handleAnalyze = async () => {
        if (!message) {
            alert("Please enter a message!");
            return;
        }

        try {
            const response = await fetch('http://127.0.0.1:5000/message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message }),
            });

            const data = await response.json();
            setAnalysis(data.analysis);
        } catch (error) {
            console.error("Error analyzing message:", error);
        }
    };

    return (
        <div className="message-analysis-container">
            <h1>Message Analysis</h1>
            <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Enter your message here..."
            />
            <button onClick={handleAnalyze}>Analyze Message</button>
            {analysis && (
                <div className="analysis-result">
                    <h2>Analysis</h2>
                    <p>{analysis}</p>
                </div>
            )}
        </div>
    );
};

export default MessageAnalysis;
