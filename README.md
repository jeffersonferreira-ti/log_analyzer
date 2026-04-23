<div align="center">

<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Focus-Log%20Analysis%20%26%20Security-8E24AA?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Version-v2.0-00C853?style=for-the-badge"/>

<br/><br/>

# Log Analyzer

**Ferramenta de análise de logs com foco em investigação operacional e segurança**

*Parse. Detect. Explain.*

</div>

---

## 🧠 O Problema

Logs contêm evidências críticas — mas são difíceis de interpretar rapidamente.

| Problema | Impacto |
|---|---|
| Alto volume de logs | Dificuldade de análise |
| Falhas repetidas passam despercebidas | Incidentes não detectados |
| Eventos isolados sem contexto | Diagnóstico impreciso |
| Falta de correlação | Visão fragmentada |

---

## 🚀 A Solução

O **Log Analyzer v2.0** transforma logs em uma análise investigativa estruturada.

Além de detectar padrões, o sistema agora:

- constrói **timeline de eventos**
- explica **drivers de risco**
- identifica **correlações entre fontes**
- organiza dados para **troubleshooting real**

---

## ⚙️ Pipeline

```text
Logs → Ingestão → Parser → Heurísticas → Score → Classificação → Investigação → JSON Report
```

---

## 🔍 Funcionalidades

### 📂 Log Ingestion

- leitura de `.log` e `.txt`
- múltiplos arquivos
- tratamento de falhas

---

### 🧩 Parsing Inteligente

Suporte a logs reais:

- Linux auth logs (`auth.log`, `secure`)
- Apache/Nginx logs
- Windows logs exportados
- fallback genérico

Extração de:

- timestamp
- nível
- mensagem
- IP

---

### 🧠 Heuristic Analysis

Detecta:

- `repeated_failed_logins`
- `repeated_errors`
- `suspicious_ip_activity`
- `critical_events_present`
- `excessive_warning_or_error_volume`

---

### 📊 Risk Scoring

| Score | Classificação |
|---|---|
| 0–19 | NORMAL |
| 20–49 | ATTENTION |
| 50–79 | SUSPICIOUS |
| 80+ | CRITICAL |

---

## 🧪 Caso de Uso Real

### 📌 Cenário

Ambiente com:

- falhas repetidas de login SSH
- erro recorrente de aplicação
- evento crítico de sistema
- atividade suspeita de IP

---

### 📊 Resultado

```text
Total Score: 91
Classification: CRITICAL

🧠 Análise Investigativa

📅 Timeline Highlights
3x Database connection failed between 10:01:15 and 10:01:20
3x Failed login from 192.168.1.50 between 10:01:22 and 10:01:42
CRITICAL Unexpected system reboot detected

⚠️ Risk Drivers
Repeated SSH authentication failures from a single IP suggest possible brute-force activity
Recurring application errors indicate persistent instability
A critical system event significantly increased overall risk
High volume of warning/error events suggests broader instability

🔗 Correlations
IP 192.168.1.50 is strongly associated with authentication failures
Authentication failures occurred close to a critical system event
Database errors were detected before system instability
Events cluster temporally before the reboot
```

---

## 🧾 JSON Report (v2.0)

Inclui:

- análise geral
- top IPs
- top erros
- agrupamento por arquivo
- timeline de eventos
- drivers de risco
- correlação entre eventos

Exemplo resumido:

```json
{
  "analysis_summary": {
    "total_score": 91,
    "classification": "CRITICAL"
  },
  "timeline_highlights": [
    "3x Failed login from 192.168.1.50 between 10:01:22 and 10:01:42"
  ],
  "risk_drivers": [
    "Repeated SSH authentication failures from a single IP suggest possible brute-force activity."
  ],
  "correlations": [
    {
      "type": "ip_correlation",
      "description": "IP 192.168.1.50 appears repeatedly in authentication failures and is a likely source of suspicious activity."
    }
  ]
}
```

---

## 🖥️ CLI

```bash
python main.py
```

Opções:

```bash
python main.py --source ./data/samples
python main.py --summary-only
python main.py --no-report
python main.py --output ./reports/analysis.json
```

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

## ⚠️ Limitações

- não substitui SIEM
- heurísticas simples
- sem correlação avançada
- não contínuo (batch analysis)

---

## 🗺️ Roadmap

| Versão | Foco | Status |
|---|---|---|
| v1.0 | Core | ✅ |
| v1.1 | Scoring | ✅ |
| v1.2 | JSON + CLI | ✅ |
| v1.3 | Logs reais | ✅ |
| v1.4 | JSON enriquecido | ✅ |
| v2.0 | Investigação (timeline + drivers + correlação) | ✅ |
| v2.1 | Monitoramento contínuo | 💡 |

---

## 🎯 Objetivo

Demonstrar:

- análise de logs em cenários reais
- identificação de padrões operacionais e de segurança
- correlação de eventos
- raciocínio investigativo

---

## 🧩 Incident Summary

This analysis indicates a scenario where:

- repeated authentication failures suggest potential brute-force activity
- recurring application errors indicate service instability
- a critical system event (reboot) occurred shortly after these issues

Together, these signals point to a **high-risk operational incident with both security and stability concerns**.

---

## 👨‍💻Desenvolvido por **Jefferson Ferreira**.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/jefferson-ferreira-ti/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/jeffersonferreira-ti)

---

<div align="center">
  <sub>Log Analyzer v2.0 · 2026</sub>
</div>
