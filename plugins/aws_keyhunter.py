# plugins/aws_keyhunter.py
import os
import importlib.util


def run(target, ip, open_ports, banners):
    """
    [DEPRECATED] Funcionalidade absorvida pelo secrets_scraper.py.
    Mantido como wrapper para retrocompatibilidade.
    """
    # Carregar secrets_scraper do mesmo diretório
    ss_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets_scraper.py")
    spec = importlib.util.spec_from_file_location("secrets_scraper", ss_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    result = mod.run(target, ip, open_ports, banners)
    # Filtrar apenas achados AWS
    aws_only = []
    if isinstance(result.get("resultados"), list):
        aws_only = [r for r in result["resultados"] if "AWS" in r.get("tipo", "")]
    return {
        "plugin": "aws_keyhunter",
        "nota": "DEPRECATED — use secrets_scraper para cobertura completa",
        "resultados": aws_only if aws_only else "Nenhuma chave AWS encontrada"
    }
