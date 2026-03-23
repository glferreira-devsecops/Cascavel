# Contribuindo com o Cascavel

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

## 🔌 Criando Plugins

Todos os plugins são funções Python puras no diretório `plugins/`. A assinatura obrigatória é:

```python
def run(target: str, ip: str, open_ports: list, banners: dict) -> dict:
    """
    Docstring descrevendo o que o plugin faz.
    """
    resultado = {}
    # ... sua lógica aqui ...
    return {"plugin": "nome_do_plugin", "resultados": resultado}
```

### Regras para Plugins

- **Assinatura**: `run(target, ip, open_ports, banners)` — exatamente 4 argumentos posicionais
- **Retorno**: Deve retornar um `dict` com chaves `"plugin"` (str) e `"resultados"` (dict/list/str)
- **Ferramentas externas**: Use `shutil.which()` para verificar disponibilidade antes de executar
- **Timeouts**: Sempre use timeouts em `subprocess.run()` e `requests.get()`
- **Erros**: Capture exceções e retorne `{"plugin": "nome", "resultados": {"erro": str(e)}}`
- **Arquivo**: Salve como `plugins/nome_do_plugin.py`

## 📝 Diretrizes de Código

- **Python 3.8+** compatível
- **Type hints** em funções públicas
- **Docstrings** descritivas em todas as funções `run()`
- **Imports**: Dentro da função `run()` para evitar erros de importação em massa
- **snake_case** para funções e variáveis
- **Sem dependências ocultas**: Documente dependências extras no docstring
- **Conventional Commits** para mensagens de commit

## 🐞 Relatando Bugs

Abra uma [Issue no GitHub](https://github.com/glferreira-devsecops/Cascavel/issues) com:

- Descrição detalhada do problema
- Passos para reproduzir
- Saída do terminal com o erro
- Versão do Python e OS

## ❓ Dúvidas?

Abra uma issue ou entre em contato com os mantenedores.

**Agradecemos sua contribuição!**
