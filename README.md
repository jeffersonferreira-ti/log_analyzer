<div align="center">

<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Focus-Log%20Analysis%20%26%20Security-8E24AA?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Status-MVP%20Complete-00C853?style=for-the-badge"/>

<br/><br/>

# Log Analyzer

**Ferramenta de analise de logs para suporte, operacoes e seguranca**

*Parse. Detect. Understand.*

</div>

---

## 🧠 O Problema

Logs sao essenciais, mas dificeis de interpretar rapidamente.

| Problema | Impacto |
|---|---|
| Grande volume de logs | Dificil identificar problemas |
| Falhas repetidas passam despercebidas | Incidentes nao detectados |
| Atividades suspeitas nao analisadas | Risco de seguranca |
| Falta de analise estruturada | Tempo alto de troubleshooting |

---

## 🚀 A Solucao

O **Log Analyzer** automatiza a analise de logs, identificando padroes relevantes como:

- falhas repetidas
- atividade suspeita de IP
- erros recorrentes
- eventos criticos

E transforma logs brutos em **insights acionaveis**.

---

## ⚙️ Como Funciona

```text
Logs -> Ingestao -> Parser -> Heuristicas -> Score -> Classificacao -> JSON Report
```

---

## 🔍 Funcionalidades

### 📂 Log Ingestion
- leitura de arquivos `.log` e `.txt`
- multiplos arquivos simultaneos
- tratamento de erros de leitura

### 🧩 Parsing
- leitura linha a linha
- tentativa de extracao de:
  - timestamp
  - nivel (`INFO`, `ERROR`, etc.)
  - mensagem
  - IP address

### 🧠 Heuristic Analysis
Detecta padroes como:

- `repeated_failed_logins`
- `repeated_errors`
- `suspicious_ip_activity`
- `critical_events_present`
- `excessive_warning_or_error_volume`

### 📊 Risk Scoring
- sistema de pontuacao baseado em heuristicas
- classificacao final:
  - `NORMAL`
  - `ATTENTION`
  - `SUSPICIOUS`
  - `CRITICAL`

### 🧾 Output
- resumo no terminal
- relatorio estruturado em JSON
- CLI configuravel

---

## 📈 Exemplo de Execucao

```bash
python main.py
```

```text
Log Analyzer is ready.
Loaded 3 log files (0 failed)
Parsed 17 log entries

Levels:
CRITICAL: 1
ERROR: 5
INFO: 4
UNKNOWN: 5
WARNING: 2

## Analysis Summary

Total Score: 91
Classification: CRITICAL
Summary: CRITICAL based on 5 triggered finding(s) across authentication, error, and event severity heuristics.

Triggered Findings:
* repeated_failed_logins [score=22]
* repeated_errors [score=14]
* suspicious_ip_activity [score=18]
* critical_events_present [score=28]
* excessive_warning_or_error_volume [score=9]

Report path: data/output/log_analysis_report.json
```

### 🧾 JSON Report

Gerado automaticamente em:

`data/output/log_analysis_report.json`

Exemplo:

```json
{
  "total_files_loaded": 3,
  "total_entries_parsed": 17,
  "analysis_summary": {
    "total_score": 91,
    "classification": "CRITICAL"
  }
}
```

### 🖥️ Uso via CLI

Execucao padrao:

```bash
python main.py
```

Diretorio customizado:

```bash
python main.py --source ./data/samples
```

Apenas resumo:

```bash
python main.py --summary-only
```

Sem gerar relatorio:

```bash
python main.py --no-report
```

Caminho customizado de saida:

```bash
python main.py --output ./reports/analysis.json
```

---

## 🧠 Analise Inteligente

O sistema interpreta padroes de log para identificar:

- tentativa de brute force
- erros recorrentes de sistema
- falhas de aplicacao
- eventos criticos de infraestrutura

---

## 🏗️ Arquitetura

```text
log_analyzer/
├── app/
│   ├── ingestor/
│   ├── parser/
│   ├── analyzer/
│   ├── reporting/
│   └── models/
├── data/
│   ├── samples/
│   └── output/
├── main.py
├── config.py
└── requirements.txt
```

---

## ▶️ Como Executar

Pre-requisitos:

- Python 3.10+
- dependencias em `requirements.txt`

```bash
pip install -r requirements.txt
python main.py
```

---

## ⚠️ Limitacoes

- nao substitui SIEMs profissionais
- nao analisa todos os formatos de log
- heuristicas simples (MVP)
- sem correlacao avancada entre eventos

---

## 🗺️ Roadmap

| Versao | Foco | Status |
|---|---|---|
| v1.0 | Ingestao + Parsing + Heuristicas | ✅ Concluido |
| v1.1 | Ajuste de scoring | ✅ Concluido |
| v1.2 | JSON report + CLI | ✅ Concluido |
| v2.0 | Integracao com logs de sistema | 📋 Planejado |
| v2.1 | Monitoramento continuo | 💡 Futuro |

---

## 🎯 Objetivo do Projeto

Projeto desenvolvido para demonstrar:

- analise de logs em ambiente real
- identificacao de padroes de erro
- deteccao de atividade suspeita
- automacao de troubleshooting
- pensamento voltado a operacoes e seguranca

---

## 👨‍💻 Sobre o Desenvolvedor

Desenvolvido por Jefferson Ferreira.

---

<div align="center">
  <sub>Log Analyzer · 2026</sub>
</div>
