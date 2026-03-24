# plugins/ftp_brute.py
import ftplib
import socket


def run(target, ip, open_ports, banners):
    """
    Scanner e brute-force básico para FTP.
    Detecta portas FTP abertas, coleta banners e tenta credenciais comuns.
    """
    _ = (ip, banners)

    ftp_default_ports = [21, 2121, 8021]
    ftp_ports_found = []
    creds_found = []

    ports_to_check = sorted(set(ftp_default_ports + [p for p in open_ports if p in ftp_default_ports]))

    for port in ports_to_check:
        s = socket.socket()
        s.settimeout(3)
        try:
            s.connect((target, port))
            banner = s.recv(1024).decode(errors="ignore")
            ftp_ports_found.append({"port": port, "banner": banner.strip()})
        except Exception:
            pass
        finally:
            s.close()

    users = ["ftp", "admin", "user", "anonymous"]
    passwords = ["ftp", "123456", "admin", "anonymous@", "password"]

    for port_info in ftp_ports_found:
        port = port_info["port"]
        for user in users:
            for passwd in passwords:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=3)
                    ftp.login(user, passwd)
                    creds_found.append({"port": port, "user": user, "pass": passwd})
                    ftp.quit()
                except Exception:
                    continue

    return {
        "plugin": "ftp_brute",
        "resultados": {
            "ftp_ports": ftp_ports_found if ftp_ports_found else "Nenhuma porta FTP aberta",
            "credenciais": creds_found if creds_found else "Nenhuma credencial encontrada",
        },
    }
