<div align="center">

<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Focus-Log%20Analysis%20%26%20Security-8E24AA?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Status-MVP%20Complete-00C853?style=for-the-badge"/>

<br/><br/>

# Log Analyzer

**Ferramenta de análise de logs para suporte, operações e segurança**

*Parse. Detect. Understand.*

</div>

---

## 🧠 O Problema

Logs são uma das principais fontes de diagnóstico em sistemas, mas analisá-los manualmente é lento e ineficiente.

| Problema | Impacto |
|---|---|
| Alto volume de logs | Difícil identificar padrões |
| Falhas repetidas passam despercebidas | Incidentes não detectados |
| Atividade suspeita não analisada | Risco de segurança |
| Falta de estrutura | Troubleshooting demorado |

---

## 🚀 A Solução

O **Log Analyzer** automatiza a análise de logs, identificando padrões relevantes e transformando dados brutos em **insights acionáveis**.

Ele combina:

- parsing estruturado
- detecção de padrões
- sistema de pontuação de risco
- classificação final do cenário analisado

---

## ⚙️ Como Funciona

```text
Logs → Ingestão → Parser → Heurísticas → Score → Classificação → JSON Report
```

---

## 🔍 Funcionalidades

### 📂 Log Ingestion
- leitura de `.log` e `.txt`
- múltiplos arquivos simultâneos
- tratamento de erros de leitura

### 🧩 Parsing Inteligente
Suporte a logs reais:

- Linux auth logs (`auth.log`, `secure`)
- Apache/Nginx logs
- Windows logs exportados (formato texto)
- fallback genérico

Extração de:

- timestamp
- nível (`INFO`, `WARNING`, `ERROR`, etc.)
- mensagem
- IP address

### 🧠 Heuristic Analysis

Detecta padrões como:

- `repeated_failed_logins`
- `repeated_errors`
- `suspicious_ip_activity`
- `critical_events_present`
- `excessive_warning_or_error_volume`

### 📊 Risk Scoring

Classificação baseada em score:

| Score | Classificação |
|---|---|
| 0-19 | NORMAL |
| 20-49 | ATTENTION |
| 50-79 | SUSPICIOUS |
| 80+ | CRITICAL |

---

## 🧪 Caso de Uso Real

### 📌 Cenário

Análise de um servidor com:

- múltiplas falhas de login SSH
- erro recorrente de aplicação
- evento crítico de sistema
- atividade suspeita de IP

### 📂 Logs analisados

- `auth.log`
- `system.log`
- `webapp.txt`

### 🔎 Resultado da análise

```text
Loaded 3 log files (0 failed)
Parsed 17 log entries

Levels:
CRITICAL: 1
ERROR: 5
INFO: 5
NOTICE: 1
WARNING: 5

📊 Análise final
Total Score: 94
Classification: CRITICAL

🚨 Findings detectados
repeated failed logins
suspicious IP activity
repeated errors
critical system event
high volume of warnings/errors
```

### 🧠 Interpretação

O sistema identificou:

- tentativa de brute force (SSH)
- comportamento suspeito de IP
- erro recorrente de aplicação
- evento crítico de sistema (reboot)
- padrão de instabilidade geral

➡️ Conclusão: cenário de risco elevado → `CRITICAL`

---

## 📈 Exemplo de Execução

```bash
python main.py
```

### 🧾 JSON Report

Gerado automaticamente em:

`data/output/log_analysis_report.json`

Exemplo simplificado:

```json
{
  "total_files_loaded": 3,
  "total_entries_parsed": 17,
  "analysis_summary": {
    "total_score": 94,
    "classification": "CRITICAL"
  }
}
```

### 🖥️ Uso via CLI

Execução padrão:

```bash
python main.py
```

Diretório customizado:

```bash
python main.py --source ./data/samples
```

Apenas resumo:

```bash
python main.py --summary-only
```

Sem relatório:

```bash
python main.py --no-report
```

Caminho customizado:

```bash
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

- não substitui SIEMs profissionais
- heurísticas simples (MVP)
- sem correlação avançada entre eventos
- parsing limitado a formatos suportados

---

## 🗺️ Roadmap

| Versão | Foco | Status |
|---|---|---|
| v1.0 | Ingestão + Parsing + Heurísticas | ✅ |
| v1.1 | Ajuste de scoring | ✅ |
| v1.2 | JSON + CLI | ✅ |
| v1.3 | Suporte a logs reais | ✅ |
| v2.0 | Enriquecimento de análise (IPs, mensagens) | 📋 |
| v2.1 | Monitoramento contínuo | 💡 |

---

## 🎯 Objetivo do Projeto

Demonstrar:

- análise de logs em ambiente real
- detecção de padrões operacionais e de segurança
- automação de troubleshooting
- raciocínio baseado em evidência

---

## 👨‍💻 Sobre o Desenvolvedor

Desenvolvido por Jefferson Ferreira

---

<div align="center">
  <sub>Log Analyzer · 2026</sub>
</div>
