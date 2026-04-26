# Analisador de Logs
É uma aplicação em Python desenvolvida para analisar arquivos de log de servidores web (como Apache ou Nginx). Ele processa os dados, identifica padrões de acesso, detecta erros e gera relatórios e gráficos para facilitar a visualização das informações.

Este projeto é ideal para estudos de análise de dados, monitoramento de sistemas e prática com manipulação de arquivos, regex e visualização de dados.
---

## Funcionalidades

* ✔️ Leitura e parsing de logs nos formatos:

  * Apache/Nginx (Common Log Format)
  * Formato simplificado
* ✔️ Identificação de:

  * IPs mais frequentes
  * Endpoints mais acessados
  * Horários de pico
  * Distribuição de erros (4xx e 5xx)
* ✔️ Geração de relatórios:

  *  TXT (relatório detalhado)
  *  CSV (dados estruturados)
* ✔️ Criação de gráficos com Matplotlib:

  * Top IPs
  * Erros por hora
  * Tráfego por hora
  * Tipos de erro
* ✔️ Geração automática de um arquivo de log de exemplo para testes

---

##  Tecnologias Utilizadas

* Python 3
* Bibliotecas padrão:

  * `re`
  * `csv`
  * `collections`
  * `datetime`
* Bibliotecas externas:

  * `matplotlib`
  * `numpy`

---

##  Estrutura do Projeto

```
log-analyzer/
│
├── log_analyzer.py        
├── sample_access.log     
├── relatorio_logs.txt     
├── relatorio_logs.csv     
├── analise_logs.png      
└── README.md              
```

---

##  Como Executar o Projeto

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/log-analyzer.git
cd log-analyzer
```

### 2. Instale as dependências

```bash
pip install matplotlib numpy
```

### 3. Execute o script

```bash
python log_analyzer.py
```

---

##  Saídas Geradas

Após a execução, o sistema irá gerar automaticamente:

* `relatorio_logs.txt` → Relatório detalhado
* `relatorio_logs.csv` → Dados estruturados
* `analise_logs.png` → Visualização gráfica

---

##  Exemplo de Uso

O próprio sistema cria um arquivo de teste (`sample_access.log`) automaticamente, permitindo executar o projeto sem precisar de dados externos.

---

##  Exemplos de Insights Gerados

* Qual IP mais acessa o servidor
* Horários com maior volume de requisições
* Taxa de erro do sistema
* Endpoints mais requisitados
* Distribuição de erros HTTP (404, 500, etc.)

---

##  Possíveis Melhorias

* Suporte a outros formatos de log
* Interface gráfica (GUI ou Web)
* Integração com banco de dados
* Exportação para dashboards (Power BI, Tableau)
* Análise em tempo real

---

