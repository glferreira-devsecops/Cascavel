# plugins/smtp_enum.py
def run(target, results):
    """
    Enumera usuários SMTP comuns via comando VRFY.
    Retorna usuários válidos ou erro, já estruturado para seu core.
    """
    import smtplib
    usuarios = ["admin", "root", "user", "contact"]
    encontrados = []
    try:
        server = smtplib.SMTP(target, 25, timeout=8)
        for usuario in usuarios:
            try:
                code, msg = server.verify(usuario)
                if code == 250:
                    encontrados.append({"usuario": usuario, "resposta": msg.decode() if isinstance(msg, bytes) else str(msg)})
            except Exception:
                continue
        server.quit()
        results["smtp_enum"] = encontrados if encontrados else "Nenhum usuário encontrado"
    except Exception as e:
        results["smtp_enum"] = {"erro": str(e)}
