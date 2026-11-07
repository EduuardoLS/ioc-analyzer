# 🛡️ IOC Analyzer & Threat Intelligence Platform

> Ferramenta modular desenvolvida em Python para análise e triagem de **Indicadores de Comprometimento (IOCs)**, contando com integração em tempo real à API do VirusTotal v3, persistência em SQLite, exportação de relatórios em JSON e testes automatizados.

---

## 🚀 Funcionalidades Principais

* **Validação de Entradas Rigorosa:** Verificação e sanitização de sintaxe para Endereços IP (v4), Domínios e Hashes criptográficos (SHA-256) utilizando expressões regulares e bibliotecas nativas de segurança.
* **Consulta de Inteligência de Ameaças:** Integração robusta com o VirusTotal v3 para checagem de reputação e estatísticas globais de detecção de antivírus.
* **Motor de Classificação de Risco:** Categorização automatizada baseada em severidade (*Baixo Risco / Limpo*, *Suspeito* e *Alto Risco*).
* **Persistência de Dados (SQLite):** Armazenamento estruturado de todo o histórico de consultas para auditoria e rastreabilidade.
* **Exportação de Relatórios (JSON):** Geração automática de arquivos de auditoria detalhados por alvo analisado.

---

## 🛠️ Tecnologias Utilizadas

* **Linguagem:** Python 3.15+
* **APIs & Protocolos:** VirusTotal API v3 (REST / HTTPS)
* **Validação e Manipulação:** `ipaddress`, `re`, `json`
* **Banco de Dados:** SQLite 3
* **Testes Automatizados:** Pytest
* **Controle de Versão:** Git & GitHub

---

## 📂 Estrutura do Projeto

```text
ioc-analyzer/
│
├── src/
│   ├── main.py            # Orquestrador do menu interativo (CLI)
│   ├── analyzer.py        # Motor de regras e classificação de risco
│   ├── validators.py      # Módulo de validação de sintaxe (IP, Domínio, Hash)
│   ├── virustotal.py      # Cliente HTTP para integração com a API do VT
│   ├── database.py        # Gerenciador de persistência SQLite
│   └── report.py          # Módulo de exportação de relatórios JSON
│
├── data/
│   ├── reports/           # Relatórios individuais exportados em JSON
│   └── history.db         # Banco de dados SQLite local (gerado automaticamente)
│
├── tests/
│   └── test_validators.py # Testes automatizados de validação
│
├── .env.example           # Template para variáveis de ambiente
├── .gitignore             # Arquivos ignorados pelo Git
├── requirements.txt       # Dependências do projeto
└── README.md              # Documentação oficial do projeto