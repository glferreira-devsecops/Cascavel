# Contribuindo com o Cascavel

<div align="center">

**Cascavel** — Quantum Security Framework
<br>Open Source by [RET Tecnologia](https://rettecnologia.org)

</div>

---

Sua colaboração é fundamental para o crescimento do **Cascavel — Quantum Security Framework**! Agradecemos seu interesse em contribuir.

## 🤝 Como Contribuir

1. **Fork** o repositório principal no GitHub.
2. **Clone** seu fork:
   ```bash
   git clone https://github.com/SEU_USUARIO/Cascavel.git
   cd Cascavel
   ```
3. **Crie um branch** para sua contribuição:
   ```bash
   git checkout -b feature/minha-feature
   ```
4. **Desenvolva** suas alterações seguindo as diretrizes abaixo.
5. **Commit** com mensagens claras (Conventional Commits):
   ```bash
   git commit -m "feat: adiciona plugin de scan X"
   git commit -m "fix: corrige assinatura do plugin Y"
   ```
6. **Push** para seu fork:
   ```bash
   git push origin feature/minha-feature
   ```
7. **Abra um Pull Request** para a branch `main` do repositório original.

## 🔌 Criando Plugins (v2.1.0)

Todos os plugins são funções Python puras no diretório `plugins/`. A assinatura obrigatória é:

```python
# plugins/meu_plugin.py
import requests


def run(target: str, ip: str, open_ports: list, banners: dict) -> dict:
    """Docstring descrevendo o que o plugin faz."""
    _ = (ip, open_ports, banners)  # Suppress unused params
    resultado = {}
    try:
        resultado["dados"] = "..."
    except Exception as e:
        resultado["erro"] = str(e)
    return {"plugin": "meu_plugin", "resultados": resultado}
```

### Regras para Plugins (v2.1.0)

- **Assinatura**: `run(target, ip, open_ports, banners)` — exatamente 4 argumentos posicionais
- **Unused params**: `_ = (ip, open_ports, banners)` no início da função para suprimir warnings
- **Imports**: No **top-level** do arquivo (nunca dentro da função `run()`)
- **Constantes**: Extraia strings duplicadas (>3x) em constantes no topo do módulo
- **Cognitive complexity**: Máximo **15 pontos** por função — use helper functions (`_nome_helper`)
- **Retorno**: Deve retornar `dict` com `"plugin"` (str) e `"resultados"` (dict/list/str)
- **Ferramentas externas**: Use `shutil.which()` para verificar disponibilidade
- **Timeouts**: Obrigatórios em `subprocess.run()` e `requests.get()`
- **Erros**: Capture exceções e retorne `{"plugin": "nome", "resultados": {"erro": str(e)}}`
- **Shell commands**: Use `shlex.quote()` para sanitizar inputs em comandos shell
- **Arquivo**: Salve como `plugins/nome_do_plugin.py`

### Saída Recomendada (v2.1.0)

Para plugins novos, inclua as chaves `versao` e `tecnicas`:

```python
return {
    "plugin": "meu_plugin",
    "versao": "2026.1",
    "tecnicas": ["header_injection", "passive_detection"],
    "resultados": {"vulns": [...], "intel": {...}},
}
```

## 📝 Diretrizes de Código

- **Python 3.8+** compatível
- **Type hints** em funções públicas
- **Docstrings** descritivas em todas as funções `run()`
- **snake_case** para funções e variáveis
- **Sem dependências ocultas**: Documente dependências extras no docstring
- **Conventional Commits** para mensagens de commit

## ⚡ Quick Install

### Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv nmap nikto
git clone https://github.com/glferreira-devsecops/Cascavel.git
cd Cascavel && python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -e ".[full]"  # Opcional: todas as dependências
```

### macOS (Homebrew)
```bash
brew install python nmap nikto
git clone https://github.com/glferreira-devsecops/Cascavel.git
cd Cascavel && python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -e ".[full]"  # Opcional: todas as dependências
```

### Windows (WSL recomendado)
```bash
# Opção 1: WSL (recomendado)
wsl --install
# Dentro do WSL, siga as instruções de Linux acima.

# Opção 2: Nativo (limitado)
# Instale Python 3.8+ via python.org
# Algumas ferramentas externas não estão disponíveis no Windows nativo.
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
```

### Ferramentas Externas (Opcionais)
```bash
# Go-based tools (require Go 1.21+)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/tomnomnom/gau@latest
```

### Verificar Instalação
```bash
python3 cascavel.py --check-tools    # Lista ferramentas detectadas
python3 cascavel.py --list-plugins   # Lista todos os 84 plugins
python3 cascavel.py -t target.com    # Executa scan completo
python3 cascavel.py --plugins-only -t target.com  # Apenas plugins (sem tools externas)
python3 cascavel.py -q -o json -t target.com      # Quiet + JSON (CI/CD)
```

## 📜 DCO — Developer Certificate of Origin

Cascavel adota o **DCO (Developer Certificate of Origin)** para garantir a integridade legal de todas as contribuições. Ao enviar um commit, você atesta que:

1. Você criou a contribuição, ou tem o direito de submetê-la sob a licença MIT
2. A contribuição é fornecida sob a licença MIT do projeto

### Como assinar

Adicione o flag `-s` ao seu commit:

```bash
git commit -s -m "feat: add new plugin for X detection"
```

Isso gera automaticamente a linha:

```
Signed-off-by: Seu Nome <seu@email.com>
```

> **Nota:** O nome e email devem corresponder aos configurados no seu Git (`git config user.name` e `git config user.email`).

## 🐞 Relatando Bugs

Abra uma [Issue no GitHub](https://github.com/glferreira-devsecops/Cascavel/issues) com:

- Descrição detalhada do problema
- Passos para reproduzir
- Saída do terminal com o erro
- Versão do Python e OS
- Saída de `cascavel --check-tools`

## ❓ Dúvidas?

Abra uma issue ou entre em contato com os mantenedores.

---

<div align="center">

**Cascavel** — Mantido por [RET Tecnologia](https://rettecnologia.org) · MIT License
<br>[GitHub](https://github.com/glferreira-devsecops) · [LinkedIn](https://linkedin.com/in/DevFerreiraG) · [Website](https://rettecnologia.org)

</div>
