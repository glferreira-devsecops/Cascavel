# plugins/smpt_enum.py
import smtplib


def run(target, ip, open_ports, banners):
    """
    Enumera usuários SMTP comuns via comando VRFY.
    Verifica porta 25 antes de tentar conexão.
    """
    _ = (ip, banners)

    usuarios = ["admin", "root", "user", "contact", "info", "postmaster", "webmaster"]
    encontrados = []

    smtp_ports = [p for p in open_ports if p in [25, 587, 465]] or [25]

    for smtp_port in smtp_ports:
        try:
            server = smtplib.SMTP(target, smtp_port, timeout=8)
            for usuario in usuarios:
                try:
                    code, msg = server.verify(usuario)
                    decoded_msg = msg.decode() if isinstance(msg, bytes) else str(msg)
                    if code == 250:
                        encontrados.append(
                            {
                                "usuario": usuario,
                                "porta": smtp_port,
                                "resposta": decoded_msg,
                            }
                        )
                except Exception:
                    continue
            server.quit()
        except Exception as e:
            encontrados.append({"porta": smtp_port, "erro": str(e)})

    return {
        "plugin": "smpt_enum",
        "resultados": encontrados if encontrados else "Nenhum usuário SMTP encontrado",
    }
