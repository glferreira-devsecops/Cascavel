## Descrição

<!-- Descreva suas alterações de forma clara e concisa. -->

## Tipo de Alteração

- [ ] 🐛 Bug fix (correção sem breaking change)
- [ ] ✨ Nova feature (funcionalidade sem breaking change)
- [ ] 🔌 Novo plugin (`plugins/nome_do_plugin.py`)
- [ ] 💥 Breaking change (alteração que quebra compatibilidade)
- [ ] 📚 Documentação
- [ ] ♻️ Refatoração (sem mudança funcional)
- [ ] ⚡ Performance
- [ ] 🔒 Segurança

## Checklist

- [ ] Meu código segue as [diretrizes de contribuição](CONTRIBUTING.md)
- [ ] Realizei self-review do meu código
- [ ] Comentei trechos complexos ou não-óbvios
- [ ] Atualizei a documentação relevante (README, PLUGINS.md, CHANGELOG)
- [ ] Minhas alterações não geram novos warnings
- [ ] Testei localmente com `python3 cascavel.py --check-tools`
- [ ] Testei com `python3 cascavel.py --list-plugins`
- [ ] Usei [Conventional Commits](https://conventionalcommits.org/) nas mensagens

## Plugin Checklist (se aplicável)

- [ ] Assinatura: `run(target, ip, open_ports, banners)` — 4 args
- [ ] `_ = (ip, open_ports, banners)` para suprimir unused warnings
- [ ] Imports no top-level (não dentro de `run()`)
- [ ] Retorna `dict` com `"plugin"` e `"resultados"`
- [ ] `shlex.quote()` em inputs de shell
- [ ] Timeouts em `subprocess.run()` e `requests`
- [ ] Erros capturados com `try/except`

## Screenshots / Output

<!-- Se aplicável, adicione screenshots ou output do terminal. -->

## Contexto Adicional

<!-- Links, issues relacionadas, motivação. -->

---

> **Cascavel** — Quantum Security Framework by [RET Tecnologia](https://rettecnologia.org)
