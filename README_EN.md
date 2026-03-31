# LLM-Driven Intelligent Detection and Risk Visualization System for Web API Broken Access Control

[中文文档](README.md)

This project is an end-to-end API authorization testing pipeline focused on Broken Access Control (IDOR + vertical privilege escalation).
It combines HAR traffic replay, DeepSeek-powered payload generation, response comparison, explainable risk scoring, and bilingual reporting artifacts.

## 1. Project Goal

Rule-based scanners are effective for syntax-level issues (e.g., SQLi/XSS), but weak in business-logic authorization flaws.
This project uses an LLM to understand API semantics, mutate identity/privilege parameters, replay attacks with preserved authentication context, and produce evidence-driven risk decisions.

## 2. Core Capabilities

1. Traffic parsing: parse HAR and extract API requests.
2. LLM mutation: generate IDOR-oriented attack payloads with DeepSeek.
3. Automated replay: keep auth headers and apply only mutation fields.
4. Risk analysis: score with status code, content similarity, JSON schema overlap, and sensitive pattern matches.
5. Mitigation generation: produce defense guidance for findings.
6. Visualization: export Markdown and HTML reports.
7. Runtime tracing: generate one detailed log file per run.

## 3. Project Structure

```text
LLM_API_Vuln_Scanner/
├── main.py
├── requirements.txt
├── README.md
├── README_EN.md
├── config/
│   ├── config.yaml
│   └── settings.py
├── core/
│   ├── parser.py
│   ├── llm_agent.py
│   ├── scanner.py
│   └── analyzer.py
├── prompts/
│   ├── idor_prompt.txt
│   └── mitigation_prompt.txt
├── data/
│   ├── input/
│   └── output/
├── report/
│   ├── report_generator.py
│   ├── output_report.md
│   ├── output_report.html
│   └── templates/
├── local_lab/
│   ├── vuln_api.py
│   ├── generate_har.py
│   └── README.md
└── logs/
```

## 4. Runtime Workflow

`main.py` executes these stages:

1. Phase 1: parse HAR and replay baseline requests.
2. Phase 2: call DeepSeek to generate authorization-bypass payloads.
3. Phase 3: replay attack payloads and analyze risk.
4. Add-on: for medium/high findings, generate mitigation guidance via LLM.
5. Export outputs: JSON artifacts, Markdown/HTML reports, and run log.

## 5. Setup

### 5.1 Install dependencies

```powershell
pip install -r requirements.txt
```

### 5.2 Configure DeepSeek key

```powershell
$env:DEEPSEEK_API_KEY="your_deepseek_key"
```

You can also set `api_key` in `config/config.yaml`, but env var is safer.

## 6. Quick Start (scan existing HAR)

1. Put HAR files into `data/input/`.
2. Set `input_har` in `config/config.yaml`.
3. Run:

```powershell
python main.py
```

## 7. Use Built-in Local Vulnerable Lab

A deliberately vulnerable local API service is included for authorized testing demos.

### 7.1 Start local lab service

```powershell
python local_lab/vuln_api.py
```

Default bind: `http://127.0.0.1:8000`

### 7.2 Generate local HAR

```powershell
python local_lab/generate_har.py
```

Output: `data/input/local_lab.har`

### 7.3 Run scanner

```powershell
python main.py
```

> Default config already points to local lab:
>
> - `target_url: http://127.0.0.1:8000`
> - `input_har: data/input/local_lab.har`

## 8. Output Artifacts

1. `data/output/phase1_replay_results.json`: baseline replay results.
2. `data/output/phase2_payloads.json`: generated payloads.
3. `data/output/phase3_attack_results.json`: attack replay results.
4. `data/output/phase3_analysis.json`: risk analysis with evidence.
5. `report/output_report.md`: Markdown report.
6. `report/output_report.html`: HTML report.

## 9. Report Contents

The report includes:

1. Risk object: endpoint method + URL.
2. Trigger condition: exact mutation with unchanged authentication context.
3. Risk evidence:
   - baseline/attack status code
   - similarity
   - schema overlap metrics (shared/baseline/overlap)
   - sensitive hits
   - baseline vs attack response preview
4. Impact analysis.
5. Conclusion: risk level + score.
6. Mitigation & prevention recommendations.

## 10. Runtime Logging

Each run creates a new log file:

- `logs/run_YYYYMMDD_HHMMSS.log`

The log records:

1. lifecycle timestamps per phase
2. HAR parsing details
3. baseline/attack replay details
4. LLM call and retry behavior
5. analyzer scoring signals
6. report export results

## 11. Safety & Compliance

1. For authorized security testing and education only.
2. Do not scan unauthorized targets.
