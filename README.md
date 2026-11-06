# Detection-as-Code (DaC) & Continuous Validation Pipeline

[![CI/CD Detection Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-blue?logo=githubactions)](.github/workflows/pr_validation.yml)
[![Sigma Rules](https://img.shields.io/badge/Sigma-Standard%20v2-orange)](rules/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Coverage%20Layer-green?logo=mitre)](mitre_coverage_layer.json)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%20%7C%203.14-blue?logo=python)](requirements.txt)

Repositório estruturado segundo princípios de **Detection Engineering** e **GitOps** para versionamento, linting, testes sintáticos com telemetria e compilação automatizada de regras Sigma para múltiplos SIEMs/Data Lakes.

---

## 🎯 Arquitetura do Pipeline

\\	ext
       [ Regras Sigma (YAML) ]
                  │
                  ▼
   ┌─────────────────────────────┐
   │ 1. Linter & Schema (pytest) │
   └──────────────┬──────────────┘
                  │ (OK)
                  ▼
   ┌─────────────────────────────┐
   │ 2. Testes de Telemetria     │ ◄── [ Logs TP / FP (.json) ]
   └──────────────┬──────────────┘
                  │ (Zero FP)
                  ▼
   ┌─────────────────────────────┐
   │ 3. Compilador pySigma       │
   └──────┬──────────────┬───────┘
          │              │
          ▼              ▼
    [ Microsoft ]    [ Splunk ]    [ Elasticsearch ]
    Sentinel (KQL)     (SPL)        (Lucene/DSL)
\
---

## 🗺️ Cobertura MITRE ATT&CK

A matriz de cobertura é recalculada a cada build através de extração automatizada das tags presentes nas regras:

* **Arquivo de Layer:** [\mitre_coverage_layer.json\](mitre_coverage_layer.json)
* **Visualização Web:** O layer pode ser aberto diretamente no [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) importando o JSON deste repositório.

### Cobertura Atual

| Tática MITRE | ID Técnica | Nome da Técnica | Regra de Detecção | Severidade |
| :--- | :--- | :--- | :--- | :--- |
| Defense Evasion | \T1105\ | Ingress Tool Transfer | Suspicious File Download via Certutil | High |

---

## ⚙️ Execução Local

\\powershell
# Ativar ambiente virtual
.\.venv\Scripts\Activate.ps1

# Executar suíte de testes (linting e telemetria)
pytest -v tests/test_rules.py

# Compilar para Sentinel, Splunk e Elastic
python scripts/compile_rules.py

# Recalcular layer MITRE ATT&CK
python scripts/generate_mitre_layer.py
\