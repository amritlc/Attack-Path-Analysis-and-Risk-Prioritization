# Automated Multi-Stage Attack Path Analysis and AI-Assisted Risk Prioritization Using Attack Graphs

> MSc Cyber Security Dissertation Project  
> University of Hertfordshire

## Project Overview

Modern enterprise networks contain numerous interconnected devices and vulnerabilities, making it difficult for security analysts to identify the most critical attack paths. Traditional vulnerability scanners report individual vulnerabilities but often fail to demonstrate how attackers can combine multiple vulnerabilities to compromise critical assets.

This project develops an automated framework that discovers multi-stage attack paths using attack graphs and prioritizes security risks with AI-assisted analysis. The framework aims to help security professionals identify the most probable attack routes and focus remediation efforts on the highest-risk vulnerabilities.

---

## Project Objectives

The objectives of this project are:

- Build a realistic enterprise network test environment.
- Collect network information using vulnerability assessment tools.
- Generate attack graphs from discovered vulnerabilities.
- Identify potential multi-stage attack paths.
- Apply AI-assisted techniques to prioritize attack paths based on risk.
- Evaluate the framework using performance and scalability metrics.

---

## Research Question

**How can automated attack graph analysis combined with AI-assisted risk prioritization improve the identification and prioritization of multi-stage cyber attack paths compared to traditional vulnerability assessment approaches?**

---

## Features

- Automated network discovery
- Vulnerability assessment integration
- Attack graph generation
- Multi-stage attack path discovery
- AI-assisted risk prioritization
- Attack graph visualization
- Experimental evaluation

---

## Technologies

### Programming

- Python 3.x

### Libraries

- NetworkX
- Pandas
- NumPy
- Matplotlib
- Scikit-learn
- PyVis
- Graphviz

### Security Tools

- Nmap
- Greenbone/OpenVAS
- Metasploit Framework

### Development Tools

- Git
- GitHub
- Visual Studio Code
- Jupyter Notebook

---

## Project Structure

```

Attack-Path-Analysis-and-Risk-Prioritization/

├── data/
│ ├── raw/
│ ├── processed/
│ └── synthetic/
│
├── docs/
│ ├── proposal/
│ ├── literature/
│ ├── ipr/
│ └── dissertation/
│
├── experiments/
│
├── images/
│
├── notebooks/
│
├── reports/
│
├── scans/
│ ├── nmap/
│ ├── openvas/
│ └── metasploit/
│
├── src/
│ ├── attack_graph/
│ ├── graph_builder/
│ ├── risk_prioritization/
│ ├── visualization/
│ ├── utils/
│ └── main.py
│
├── tests/
│
├── README.md
├── requirements.txt
└── .gitignore

```

---

## Installation

Clone the repository

```bash
git clone https://github.com/yourusername/Attack-Path-Analysis-and-Risk-Prioritization.git
```

Navigate into the project

```bash
cd Attack-Path-Analysis-and-Risk-Prioritization
```

Create a virtual environment

```bash
python -m venv venv
```

Activate the virtual environment

### Windows

```bash
venv\Scripts\activate
```

### Linux/macOS

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## Current Progress

### Phase 1 – Project Planning

- [x] Research topic finalized
- [x] Literature review started
- [x] Project proposal completed
- [x] GitHub repository created
- [ ] Development environment configured

### Phase 2 – Data Collection

- [ ] Enterprise network simulation
- [ ] Nmap scans
- [ ] OpenVAS vulnerability scans
- [ ] Dataset preparation

### Phase 3 – Framework Development

- [ ] Attack graph generation
- [ ] Multi-stage attack path discovery
- [ ] AI-assisted risk prioritization
- [ ] Visualization module

### Phase 4 – Evaluation

- [ ] Experimental setup
- [ ] Performance analysis
- [ ] Scalability evaluation
- [ ] Accuracy evaluation

### Phase 5 – Dissertation

- [ ] Interim Progress Report
- [ ] Final implementation
- [ ] Dissertation writing
- [ ] Final submission

---

## Expected Outcomes

- Automated attack graph generation
- Identification of multi-stage attack paths
- AI-assisted risk prioritization
- Interactive visualization of attack paths
- Experimental evaluation against traditional approaches

---

## Author

**Amrit Lamichhane**

MSc Cyber Security  
University of Hertfordshire

---

## Supervisor

*Saeid Gorgin*

---

## License

This project is developed for academic research purposes as part of an MSc Cyber Security dissertation.