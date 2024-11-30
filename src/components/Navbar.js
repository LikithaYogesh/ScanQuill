import React from "react";
import { Link } from "react-router-dom";
import "./Navbar.css";

const Navbar = () => {
  return (
    <nav className="navbar">
      <div className="navbar-logo">ScanQuill</div>
      <div className="navbar-links">
        <Link to="/">Home</Link>
        <Link to="/pdfscan">PDF Scan</Link>
        <Link to="/messageanalysis">Message Analysis</Link>
      </div>
    </nav>
  );
};

export default Navbar;
