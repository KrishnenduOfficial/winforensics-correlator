# Windows Forensic Timeline Correlator

![Status](https://img.shields.io/badge/Status-In%20Development-yellow?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-Passing-success?style=flat-square)

A production-grade Python command-line utility built for SOC analysts and incident responders. This tool correlates high-value Windows artifact execution evidence (**Amcache, Shimcache, BAM/DAM**) against file system timelines to detect sophisticated anti-forensics techniques such as **timestomping** and **execution-without-file-presence**, while providing precise **user SID attribution**.

---

## 🚀 Project Overview

During forensic investigations, correlating *when* a binary was executed with *when* its file system metadata claims it was modified is critical. Attackers frequently alter timestamps (timestomping) or clear logs post-execution. 

The **Windows Forensic Timeline Correlator** automates multi-artifact ingestion, normalizes heterogeneous timestamps into a unified schema (`TimelineEntry`), attributes executions to specific user accounts via Windows SIDs, and flags temporal anomalies.

---

## 🛠️ Tech Stack & Libraries

* **Language:** Python 3.10+
* **CLI Framework:** `Click` & `Rich` (for colorized terminal dashboards)
* **Registry Parsing:** `python-registry` (Amcache, Shimcache binary carving, BAM/DAM)
* **Testing:** `pytest` (comprehensive unit test coverage with mocked registry hives)

---

## 📂 Architecture & Core Modules

* **`models/schema.py`**: Defines the universal `TimelineEntry` dataclass, supporting standard timestamps, file paths, hashes, and **user SID attribution**.
* **`parsers/amcache_parser.py`**: Streams application execution metadata and SHA-1 hashes from `Amcache.hve`.
* **`parsers/shimcache_parser.py`**: Features a custom structure-agnostic byte carver targeting Windows 10/11 (`'10ts'`) binary entries.
* **`parsers/bam_parser.py`**: Extracts Background Activity Moderator (BAM) and Desktop Activity Moderator (DAM) execution records linked with user SIDs.

---

## 🗺️ Development Roadmap & Status

- [x] **Phase 1:** Project architecture, virtual environment, and unified schema design (`TimelineEntry`)
- [x] **Phase 2:** Execution artifact parsers (Amcache, Shimcache byte-carver, BAM/DAM with SID attribution) & Pytest suite
- [ ] **Phase 3:** SRUM & Master File Table ($MFT) timeline parsers
- [ ] **Phase 4:** Correlation engine & anomaly detection logic (Timestomping, privilege-to-path mismatches)
- [ ] **Phase 5:** Rich CLI dashboard, reporting modules, and integration tests

---

## ⚙️ Installation & Setup

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