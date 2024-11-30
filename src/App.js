import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Home from './components/Home';
import PdfScan from './components/PdfScan';
import MessageAnalysis from './components/MessageAnalysis';
import Navbar from './components/Navbar';

const App = () => {
    return (
        <Router>
            <Navbar />
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/pdfscan" element={<PdfScan />} />
                <Route path="/messageanalysis" element={<MessageAnalysis />} />
            </Routes>
        </Router>
    );
};

export default App;
