# Windows Forensic Timeline Correlator

![Status](https://img.shields.io/badge/Status-In%20Development-yellow?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A production-grade Python command-line utility built for SOC analysts and incident responders. This tool correlates high-value Windows artifact execution evidence (**Amcache, Shimcache, BAM/DAM**) against Master File Table (**$MFT**) file system timestamps to detect sophisticated anti-forensics techniques such as **timestomping** and **execution-without-file-presence**.

---

## 🚀 Project Overview

During forensic investigations, correlating *when* a binary was executed with *when* its file system metadata claims it was created or modified is critical. Attackers frequently alter timestamps (timestomping) or clean up binaries post-execution. 

The **Windows Forensic Timeline Correlator** automates this multi-artifact ingestion, normalizes timestamps into a unified schema, and flags temporal anomalies with a confidence-scoring engine.

---

## 🛠️ Tech Stack & Libraries

* **Language:** Python 3.10+
* **CLI Framework:** `Click` & `Rich` (for professional, colorized terminal dashboards)
* **Registry Parsing:** `python-registry` (Amcache, BAM/DAM parsing)
* **NTFS Parsing:** `dissect.ntfs` ($MFT analysis)
* **Testing:** `pytest` & `pytest-cov`

---

## 🗺️ Development Roadmap & Status

This project is actively being built out in structured engineering phases:

- [x] **Phase 1:** Project architecture, virtual environment, and unified schema design (`TimelineEntry`)
- [ ] **Phase 2:** Amcache & Shimcache artifact parsers
- [ ] **Phase 3:** MFT timeline parser & core correlation engine
- [ ] **Phase 4:** Anomaly detection logic (Timestomping Generations 1–3, 5)
- [ ] **Phase 5:** Rich CLI dashboard, reporting modules, and unit test suite

---

## ⚙️ Installation & Setup (In Progress)

To set up the development environment locally:

```bash
# Clone the repository
git clone [https://github.com/krishnendu1986162002/winforensics-correlator.git](https://github.com/krishnendu1986162002/winforensics-correlator.git)
cd winforensics-correlator

# Create and activate virtual environment
python -m venv .venv
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt