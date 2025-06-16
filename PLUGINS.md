# 🛡️ Framework Cascavel - Documentação de Plugins

## 📋 Sumário
- [Visão Geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Plugins Disponíveis](#plugins-disponíveis)
- [Desenvolvimento](#desenvolvimento)
- [Segurança](#segurança)
- [Contribuição](#contribuição)
- [Suporte](#suporte)

## 🎯 Visão Geral

O Framework Cascavel é uma solução modular de segurança cibernética que permite a execução de testes de penetração automatizados através de plugins. Esta documentação detalha a implementação, uso e desenvolvimento de plugins para o framework.

### 🎯 Objetivos
- Fornecer uma interface padronizada para testes de segurança
- Facilitar a integração de novas ferramentas de segurança
- Manter a consistência e qualidade dos testes
- Garantir a rastreabilidade dos resultados

### 🔧 Requisitos do Sistema
- Python 3.8+
- Dependências listadas em `requirements.txt`
- Permissões adequadas para execução de testes de rede

## 🏗️ Arquitetura

### Estrutura do Plugin
```python
from typing import List, Dict, Any
import logging

class CascavelPlugin:
    def __init__(self):
        self.name = "Nome do Plugin"
        self.version = "1.0.0"
        self.description = "Descrição do plugin"
        self.author = "Seu Nome"
        self.logger = logging.getLogger(self.name)

    def run(self, target: str, ip: str, open_ports: List[int], banners: Dict[int, str]) -> Dict[str, Any]:
        """
        Executa o teste de segurança do plugin.
        
        Args:
            target (str): Hostname ou IP do alvo
            ip (str): Endereço IP resolvido
            open_ports (List[int]): Lista de portas abertas
            banners (Dict[int, str]): Dicionário de banners das portas
            
        Returns:
            Dict[str, Any]: Resultados do teste em formato estruturado
        """
        try:
            # Implementação do plugin
            return {
                "status": "success",
                "data": {},
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "plugin_version": self.version
                }
            }
        except Exception as e:
            self.logger.error(f"Erro na execução: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "plugin_version": self.version
                }
            }
```

## 🔍 Plugins Disponíveis

### 🛡️ Segurança de Rede
| Plugin | Versão | Descrição | Dependências |
|--------|---------|------------|--------------|
| `admin_finder.py` | 1.0.0 | Localizador de painéis administrativos | requests, beautifulsoup4 |
| `subdomain_takeou.py` | 1.0.0 | Detecção de takeover de subdomínios | dns.resolver, requests |
| `waf_detec.py` | 1.0.0 | Detecção de WAF | requests, re |
| `nmap_advanc.py` | 1.0.0 | Varredura avançada | python-nmap |
| `heartbleed_scanner.py` | 1.0.0 | Scanner Heartbleed | scapy |
| `domain_transf.py` | 1.0.0 | Detecção de transferência | dns.resolver |

### 🌐 Segurança Web
| Plugin | Versão | Descrição | Dependências |
|--------|---------|------------|--------------|
| `wps_scanmini.py` | 1.0.0 | Scanner WordPress | requests, re |
| `tech_fingerprint.py` | 1.0.0 | Identificação de tecnologias | requests, wappalyzer |
| `sqli_scanner.py` | 1.0.0 | Scanner SQL Injection | requests, re |
| `dir_bruteforce.py` | 1.0.0 | Força bruta de diretórios | requests, concurrent.futures |
| `fast_webshell.py` | 1.0.0 | Detecção de webshells | yara-python |

### 🔐 Autenticação e Acesso
| Plugin | Versão | Descrição | Dependências |
|--------|---------|------------|--------------|
| `ssh_brute.py` | 1.0.0 | Teste SSH | paramiko |
| `ftp_brute.py` | 1.0.0 | Teste FTP | ftplib |
| `smb_ad.py` | 1.0.0 | Teste SMB/AD | impacket |
| `smpt_enum.py` | 1.0.0 | Enumeração SMTP | socket |

### ☁️ Segurança em Nuvem
| Plugin | Versão | Descrição | Dependências |
|--------|---------|------------|--------------|
| `s3_bucket.py` | 1.0.0 | Teste S3 | boto3 |
| `aws_keyhunter.py` | 1.0.0 | Detecção de chaves AWS | boto3, re |
| `cloud_enum.py` | 1.0.0 | Enumeração de serviços | boto3, azure-mgmt |

## 💻 Desenvolvimento

### Estrutura de Diretórios
```
plugins/
├── __init__.py
├── base/
│   └── plugin_base.py
├── network/
│   ├── __init__.py
│   └── admin_finder.py
├── web/
│   ├── __init__.py
│   └── wps_scanmini.py
└── tests/
    └── test_plugins.py
```

### Padrões de Código
1. **Nomenclatura**
   - Use snake_case para funções e variáveis
   - Use PascalCase para classes
   - Prefixe funções privadas com underscore

2. **Documentação**
   - Docstrings em formato Google
   - Comentários explicativos em seções complexas
   - Type hints em todas as funções

3. **Tratamento de Erros**
   - Use exceções específicas
   - Implemente logging adequado
   - Forneça mensagens de erro claras

### Exemplo de Implementação
```python
from typing import List, Dict, Any
from datetime import datetime
import logging
from .base.plugin_base import CascavelPlugin

class AdminFinderPlugin(CascavelPlugin):
    def __init__(self):
        super().__init__()
        self.name = "Admin Finder"
        self.version = "1.0.0"
        self.description = "Localiza painéis administrativos em websites"
        self.author = "DevFerreiraG"
        
    def run(self, target: str, ip: str, open_ports: List[int], banners: Dict[int, str]) -> Dict[str, Any]:
        """
        Executa a busca por painéis administrativos.
        
        Args:
            target: Hostname ou IP do alvo
            ip: Endereço IP resolvido
            open_ports: Lista de portas abertas
            banners: Dicionário de banners das portas
            
        Returns:
            Dict contendo os resultados da busca
        """
        try:
            # Implementação do plugin
            return {
                "status": "success",
                "data": {
                    "admin_panels": [],
                    "scan_time": datetime.now().isoformat()
                },
                "metadata": {
                    "plugin_version": self.version,
                    "target": target
                }
            }
        except Exception as e:
            self.logger.error(f"Erro na busca de painéis admin: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "metadata": {
                    "plugin_version": self.version,
                    "target": target
                }
            }
```

## 🔒 Segurança

### Boas Práticas
1. **Autenticação e Autorização**
   - Sempre verifique permissões antes de executar testes
   - Use credenciais de forma segura
   - Implemente rate limiting

2. **Proteção de Dados**
   - Não armazene dados sensíveis
   - Use criptografia quando necessário
   - Siga LGPD e outras regulamentações

3. **Responsabilidade**
   - Obtenha autorização antes de testar
   - Documente todas as ações
   - Mantenha logs de auditoria

## 🤝 Contribuição

### Processo de Contribuição
1. Fork o repositório
2. Crie uma branch para sua feature
3. Implemente suas mudanças
4. Adicione testes
5. Atualize a documentação
6. Envie um Pull Request

### Checklist de Qualidade
- [ ] Código segue os padrões PEP 8
- [ ] Testes unitários implementados
- [ ] Documentação atualizada
- [ ] Logs implementados
- [ ] Tratamento de erros adequado
- [ ] Dependências documentadas

## 📞 Suporte

### Canais de Suporte
- GitHub Issues
- Email: suporte@cascavel.com
- Discord: [Link do Servidor]

### Recursos Adicionais
- [Documentação Completa](https://docs.cascavel.com)
- [Tutoriais](https://tutorials.cascavel.com)
- [FAQ](https://faq.cascavel.com)

---

## 📝 Notas de Versão

### v1.0.0 (2024-03-20)
- Lançamento inicial do framework
- Implementação dos primeiros plugins
- Documentação básica

### v1.1.0 (Em Desenvolvimento)
- Novos plugins planejados
- Melhorias de performance
- Expansão da documentação

---

## 📜 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

*Desenvolvido com ❤️ por DevFerreiraG* 