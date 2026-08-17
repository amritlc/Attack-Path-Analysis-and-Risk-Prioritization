# Automated Multi-Stage Attack Path Analysis and AI-Assisted Risk Prioritization Using Attack Graphs

> MSc Cyber Security Dissertation Project  
> University of Hertfordshire

## Project Overview

Traditional vulnerability assessment tools such as Nmap and Greenbone/OpenVAS provide valuable information about individual hosts, services and vulnerabilities. However, isolated vulnerability lists do not directly show how weaknesses across interconnected systems may contribute to multi-stage routes towards a critical asset.

This project develops a reproducible graph-based cybersecurity analysis framework for identifying and prioritising multi-stage attack paths within a controlled virtual laboratory.

The framework integrates:

- Nmap network and service discovery data
- Greenbone/OpenVAS vulnerability findings
- National Vulnerability Database (NVD) enrichment
- Exploit Prediction Scoring System (EPSS) evidence
- CISA Known Exploited Vulnerabilities (KEV) evidence
- NetworkX-based attack graph construction
- Source-to-critical-target attack-path enumeration
- CVSS-only baseline prioritisation
- Weight-free multi-evidence Pareto prioritisation
- AI-assisted CVE-to-MITRE ATT&CK behavioural enrichment
- Public benchmark validation
- Runtime, scalability and edge-case evaluation

The framework deliberately distinguishes **verified reachability**, **candidate compromise opportunities**, and **critical-target reachability**. A reachable service or scanner-reported vulnerability is not automatically treated as proof that a host has been compromised.

---

## Research Question

**How effectively can an automated graph-based attack-path analysis framework, using multi-evidence risk prioritisation supported by AI-derived MITRE ATT&CK context, identify and prioritise high-risk multi-stage paths to critical assets compared with a host-based vulnerability assessment baseline?**

---

## Project Objectives

1. Investigate attack-graph methodologies, multi-stage cyberattacks, contextual vulnerability prioritisation and AI-assisted cybersecurity analysis.

2. Develop a reproducible Python framework that integrates network discovery data, vulnerability findings, security intelligence, attack-graph construction and source-to-target attack-path generation.

3. Implement transparent multi-evidence attack-path prioritisation using CVSS, EPSS and CISA KEV evidence without manually assigned risk weights.

4. Integrate an AI-assisted CVE-to-MITRE ATT&CK classification model to provide behavioural context for vulnerability-supported attack paths.

5. Evaluate the framework using host-based and CVSS baselines, feature ablation, AI classification metrics, public benchmarks, runtime measurements, scalability experiments and edge-case testing.

---

## Framework Architecture

```text
Nmap scan exports
        +
OpenVAS scan exports
        |
        v
Data parsing and normalisation
        |
        v
NVD + EPSS + CISA KEV enrichment
        |
        v
Master vulnerability dataset
        |
        v
Asset / Service / Vulnerability attack graph
        |
        v
Verified reachability modelling
        |
        v
Attack-step construction
        |
        v
Source-to-critical-target path enumeration
        |
        +---------------------------+
        |                           |
        v                           v
CVSS baseline              Path evidence extraction
                                    |
                                    v
                           CVSS + EPSS + KEV
                                    |
                                    v
                         Weight-free Pareto analysis
                                    |
                                    v
                          Prioritised attack paths
                                    |
                                    v
                  AI CVE -> MITRE ATT&CK enrichment
                                    |
                                    v
                    Behavioural context for analysts
```

---

## Attack-Graph Model

The current graph uses four main concepts.

### Asset Nodes

Represent systems in the experimental network.

Examples:

```text
Application Server
Database Server
Kali Attacker
Metasploitable
OWASP Broken Web Applications
```

### Service Nodes

Represent discovered network services such as HTTP, SSH and MySQL.

### Vulnerability Nodes

Represent scanner findings and CVE-linked vulnerability evidence.

### Relationships

```text
asset -> service
hosts_service

source asset -> destination service
can_reach

service -> vulnerability
has_vulnerability

vulnerability -> asset
affects
```

Attack-path analysis subsequently derives:

```text
candidate_compromise
target_reach
```

`candidate_compromise` indicates a vulnerability-supported transition opportunity. It does **not** claim that exploitation was successfully performed.

`target_reach` represents verified service-level reachability to the designated critical asset.

---

## Experimental Laboratory

The controlled laboratory contains five documented assets:

| IP Address | Asset | Role | Criticality |
|---|---|---|---|
| 192.168.100.4 | Application Server | Application server | High |
| 192.168.100.5 | Database Server | Critical target | Critical |
| 192.168.100.6 | Kali Attacker | Attacker | N/A |
| 192.168.100.7 | Metasploitable | Vulnerable server | Medium |
| 192.168.100.8 | OWASP BWA | Web application | High |

Connectivity used by the framework is based on experimentally verified service-level reachability stored in:

```text
data/manual/connectivity.csv
```

---

## Data Sources

### Primary Laboratory Data

```text
Nmap
Greenbone/OpenVAS
manual asset metadata
verified connectivity tests
```

### External Security Intelligence

```text
National Vulnerability Database (NVD)
Exploit Prediction Scoring System (EPSS)
CISA Known Exploited Vulnerabilities (KEV)
```

### AI Dataset

A labelled CVE-to-MITRE ATT&CK dataset is used to train and evaluate the behavioural classification model.

### Public Validation References

```text
DARPA 2000 LLDOS 1.0
MulVAL 3-host example
NOMS 2022 attack-path material
```

The laboratory dataset is therefore the primary experimental environment, while public data is used for vulnerability enrichment, machine-learning evaluation and complementary external validation.

---

## Risk Prioritisation

### CVSS Baseline

A transparent CVSS-only baseline is retained for comparison.

In the laboratory experiment:

```text
P002 -> Rank 1
P003 -> Rank 1
P005 -> Rank 1
P004 -> Rank 2
```

The CVSS-only baseline therefore produced a three-way highest-priority tie.

### Multi-Evidence Pareto Prioritisation

The final framework uses:

```text
CVSS
EPSS
CISA KEV
```

The evidence dimensions are compared using Pareto dominance.

No manually assigned weighting coefficients are used.

The resulting laboratory ordering is:

```text
Front 1 -> P002

Front 2 -> P003
           P005

Front 3 -> P004
```

P001 is retained separately as direct target exposure because no vulnerability-supported compromise step exists for that path.

The Pareto approach reduced the highest-priority group from three CVSS-tied paths to one Front-1 path without introducing arbitrary risk weights.

---

## AI-Assisted Behavioural Enrichment

Artificial Intelligence is used as an **assistive behavioural-enrichment component**.

AI does not directly determine the Pareto risk ordering.

The workflow is:

```text
NVD CVE description
        |
        v
TF-IDF text representation
        |
        v
One-vs-Rest Logistic Regression
        |
        v
Multi-label MITRE ATT&CK prediction
```

A validation-selected classification threshold is used instead of relying only on the default threshold.

### Test-Set Performance

| Metric | Default Threshold | Validation-Tuned Threshold |
|---|---:|---:|
| Micro Precision | 0.9057 | 0.4499 |
| Micro Recall | 0.0787 | 0.4639 |
| Micro F1 | 0.1448 | **0.4568** |
| Macro F1 | 0.0475 | 0.2010 |
| Hamming Loss | 0.0577 | 0.0685 |

Threshold tuning substantially increased recall and Micro-F1 while reducing precision.

The tuned model is therefore used because it provides a more balanced precision-recall trade-off for behavioural enrichment.

### Laboratory Prediction Coverage

```text
Laboratory CVEs analysed:       77
CVEs with >=1 prediction:       72
CVEs without prediction:         5
Prediction coverage:           93.5%
```

**Prediction coverage is not classification accuracy.**

It only indicates the proportion of laboratory CVEs receiving at least one ATT&CK prediction above the selected threshold.

---

## Laboratory Attack-Path Results

Five distinct attacker-to-database asset routes were identified.

```text
P001
Kali -> Database


P002
Kali -> Metasploitable -> Database


P003
Kali -> Metasploitable -> OWASP BWA -> Database


P004
Kali -> OWASP BWA -> Database


P005
Kali -> OWASP BWA -> Metasploitable -> Database
```

Measured graph-analysis results:

```text
Documented/scanned vulnerable hosts:   4
Source-to-target paths:                5
Multi-stage paths:                     4
Direct target-exposure paths:          1
Attack-path steps:                    11
Candidate-compromise steps:            6
Unique compromise transitions:         4
Target-reach steps:                    5
```

The graph analysis adds source-to-target and multi-stage relationship information that is not represented by the defined isolated host-based vulnerability baseline.

---

## Feature Ablation

Single-feature ablation was performed to examine the contribution of CVSS, EPSS and KEV evidence.

```text
Remove CVSS -> 0 path-front changes

Remove EPSS -> 0 path-front changes

Remove KEV  -> P004 changes
               Front 3 -> Front 2
```

P002 remained in Front 1 under every single-feature removal.

The result indicates that KEV contributed additional discrimination in this laboratory dataset. It does not imply that KEV is universally more important than CVSS or EPSS.

---

## Public Benchmark Validation

Three public references are used for complementary validation.

### DARPA LLDOS 1.0

```text
Defined benchmark stages recovered: 5 / 5
Stage order preserved:             Yes
```

This represents recovery of the five documented campaign stages under the defined observable criteria. It is not claimed as 100% attack-detection accuracy.

### MulVAL 3-Host

```text
Directly comparable checks passed: 7 / 7
Unsupported NFS-specific relations: 3
```

Unsupported logical relations are preserved as limitations rather than fabricated into the graph.

### NOMS 2022

```text
Held-out CVE -> ATT&CK mappings recovered: 2 / 2
```

The two benchmark CVEs were removed from the benchmark training data before prediction.

Because the three public references evaluate different system properties, their results are **not averaged into a single overall accuracy value**.

---

## Runtime Evaluation

The complete post-collection analytical pipeline was executed five times.

```text
Runs:       5
Mean:      12.086 seconds
Median:    12.062 seconds
Minimum:   11.717 seconds
Maximum:   12.395 seconds
```

The runtime evaluation excludes live Nmap/OpenVAS scan duration and offline ML model training.

---

## Scalability Evaluation

Controlled synthetic scalability testing was performed on the current graph-construction and attack-path enumeration core.

Synthetic vulnerability nodes are used only to increase graph size. They are not presented as real CVEs or vulnerability observations.

| Scenario | Hosts | Vulnerability Nodes | Graph Nodes | Graph Edges | Paths |
|---|---:|---:|---:|---:|---:|
| S1 | 5 | 15 | 23 | 33 | 6 |
| S2 | 10 | 80 | 98 | 168 | 36 |
| S3 | 20 | 360 | 398 | 738 | 171 |
| S4 | 40 | 1,520 | 1,598 | 3,078 | 741 |
| S5 | 80 | 6,240 | 6,398 | 12,558 | 3,081 |

Largest tested scenario:

```text
Hosts:                         80
Synthetic vulnerability nodes: 6,240
Graph nodes:                    6,398
Graph edges:                   12,558
Generated paths:                3,081
Median execution time:          0.3449 seconds
Mean peak traced memory:        7.69 MB
```

These measurements demonstrate computational behaviour under the defined deterministic synthetic topology. They should not be interpreted as a general complexity bound for arbitrary enterprise attack graphs.

---

## Edge-Case Validation

Automated tests cover important edge conditions.

```text
Disconnected component
-> no false attacker-to-target path is generated

Repeated vulnerability evidence
-> duplicate evidence does not create duplicate semantic paths

Multiple routes to the same critical asset
-> represented by P001-P005
```

---

## Project Structure

```text
Attack-Path-Analysis-and-Risk-Prioritization/
|
|-- data/
|   |-- raw/
|   |-- manual/
|   |-- processed/
|   `-- synthetic/
|
|-- docs/
|   |-- proposal/
|   |-- literature/
|   |-- ipr/
|   `-- dissertation/
|
|-- experiments/
|   |-- evaluation_plan.csv
|   `-- final_results.csv
|
|-- images/
|   |-- evaluation/
|   `-- highest_priority_attack_path.png
|
|-- models/
|   `-- cve2attack/
|
|-- scans/
|   |-- nmap/
|   |-- openvas/
|   `-- metasploit/
|
|-- src/
|   |-- attack_graph/
|   |-- benchmark/
|   |-- data_processing/
|   |-- evaluation/
|   |-- graph_builder/
|   |-- risk_prioritization/
|   |-- visualization/
|   `-- main.py
|
|-- tests/
|
|-- README.md
|-- requirements.txt
|-- LICENSE
`-- .gitignore
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/amritlc/Attack-Path-Analysis-and-Risk-Prioritization.git
```

Move into the project:

```bash
cd Attack-Path-Analysis-and-Risk-Prioritization
```

Create a virtual environment:

```bash
python -m venv venv
```

### Windows

```powershell
venv\Scripts\activate
```

### Linux/macOS

```bash
source venv/bin/activate
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

## Running the Framework

Nmap and OpenVAS data acquisition is performed before the analytical pipeline.

The exported scan evidence is then processed using the end-to-end post-scan framework:

```bash
python -m src.main
```

The main pipeline performs:

```text
scan parsing
-> vulnerability normalisation
-> NVD/EPSS/KEV enrichment
-> master dataset generation
-> attack graph construction
-> attack-step construction
-> path enumeration
-> path evidence extraction
-> CVSS baseline
-> Pareto prioritisation
-> ATT&CK prediction
-> path behavioural enrichment
-> visualisation
```

The command stops if an individual pipeline stage fails.

---

## Running the Tests

Run the complete automated test suite:

```bash
pytest -v
```

Tests cover:

```text
data-processing consistency
graph structure and relationships
attack-path generation
risk prioritisation
AI behavioural context
public benchmark validation
evaluation outputs
scalability evidence
edge cases
required figures
```

---

## Evaluation Outputs

Final experimental evidence is stored primarily under:

```text
data/processed/lab/evaluation/
experiments/
images/evaluation/
```

The consolidated result table is:

```text
experiments/final_results.csv
```

The experiment definitions are stored in:

```text
experiments/evaluation_plan.csv
```

---

## Key Figures

The final project includes visualisations for:

```text
Experimental network architecture
Generated attack-path structure
Highest-priority attack path
CVSS-only vs Pareto prioritisation
Feature ablation
AI model comparison
AI path prediction coverage
Runtime by analytical stage
Scalability runtime
Scalability memory
```

---

## Current Project Status

### Technical Framework

- [x] Controlled virtual laboratory
- [x] Nmap data collection
- [x] OpenVAS data collection
- [x] NVD enrichment
- [x] EPSS enrichment
- [x] CISA KEV enrichment
- [x] Master dataset construction
- [x] Attack graph generation
- [x] Verified reachability integration
- [x] Multi-stage attack-path generation
- [x] CVSS baseline
- [x] Pareto prioritisation
- [x] Feature ablation
- [x] AI CVE-to-ATT&CK enrichment
- [x] DARPA benchmark validation
- [x] MulVAL benchmark validation
- [x] NOMS benchmark validation
- [x] Runtime evaluation
- [x] Scalability evaluation
- [x] Edge-case validation
- [x] End-to-end pipeline
- [x] Automated testing

### Dissertation

- [x] Detailed Project Proposal
- [x] Interim Progress Report
- [ ] Final dissertation
- [ ] Final presentation / viva preparation

---

## Important Interpretation Boundaries

The framework intentionally uses conservative terminology.

```text
Reachability != compromise

Vulnerability finding != successful exploitation

Candidate compromise != confirmed compromise

EPSS != probability that a complete attack path will succeed

AI classification confidence != cyber-risk probability

Prediction coverage != model accuracy

Benchmark recovery != overall framework accuracy
```

These distinctions are maintained throughout the implementation and evaluation.

---

## Scope and Limitations

The framework has been developed and evaluated within a small controlled virtual laboratory.

The primary laboratory contains five documented assets and should not be presented as representative of a full enterprise deployment.

The scalability experiment uses controlled synthetic graph inputs rather than additional scanned enterprise networks.

The CVE-to-ATT&CK classifier provides useful behavioural enrichment, but Macro-F1 remains limited and performance varies across ATT&CK labels.

The framework identifies evidence-supported candidate attack paths. It does not automatically exploit vulnerabilities or claim that every identified candidate transition would result in successful compromise.

Public benchmarks provide complementary validation but evaluate different aspects of the framework and therefore cannot be combined into a single overall accuracy measure.

---

## Responsible Use

This project is intended exclusively for authorised cybersecurity research, education and defensive analysis.

Experiments are conducted within a controlled laboratory using systems owned or explicitly prepared for testing.

The framework does not provide automated exploitation functionality.

Users are responsible for ensuring that network scanning and security testing are performed only with appropriate authorisation and in accordance with applicable law.

---

## Author

**Amrit Lamichhane**
MSc Cyber Security  
University of Hertfordshire

---

## Supervisor

**Saeid Gorgin**

---

## License

This repository is developed as part of an MSc Cyber Security research project.

See the repository `LICENSE` file for the applicable software licence.