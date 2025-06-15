# Cascavel Framework

Ferramenta CLI/AI de segurança para pentests, bug bounties, blue team e mais.

## Pré-requisitos

- Python 3.8 ou superior instalado  
- `git` para clonar o repositório  

## Instalação

1. Clone o repositório:  
   ```bash
   git clone https://github.com/futurodevjunior/cascavel.git
   cd cascavel
   ```
2. Crie e ative um ambiente virtual (recomendado):  
   ```bash
   python3 -m venv venv
   source venv/bin/activate    # Linux/macOS
   venv\Scripts\activate       # Windows
   ```
3. Instale as dependências:  
   ```bash
   pip install -r requirements.txt
   ```

## Estrutura de diretórios

- `cascavel_framework.py`  → Script principal  
- `requirements.txt`       → Dependências do projeto  
- `~/cascavel_exports`      → Arquivos exportados (dumps, credenciais)  
- `~/cascavel_reports`      → Relatórios em Markdown gerados  
- `~/cascavel_plugins`      → Plugins personalizados em Python  

## Uso básico

1. Execute o script principal:  
   ```bash
   python cascavel_framework.py
   ```
2. Siga as instruções interativas:  
   - Defina o **mode** (cli, server ou agent)  
   - Informe o **target** (IP ou domínio)  
   - Escolha opções de persistência, pivot e exfiltração, se desejar  
3. Relatório Markdown será salvo em `~/cascavel_reports`.

## Plugins

- Qualquer arquivo `.py` copiado para `~/cascavel_plugins` será carregado automaticamente.  
- Plugins devem exportar uma função `run(target, context)`.

## Exemplo de execução

```bash
$ python cascavel_framework.py
Mode (cli/server/agent): cli
Target (IP/domain): example.com
[Recon] DNS info for example.com:
...
[Scan] Scanning ports on example.com: [21,22,80,...]
[Open] 80
...
```

## Licença

```text
MIT License

Copyright (c) 2025 DevFerreiraG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
