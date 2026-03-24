# plugins/git_dumper.py — Cascavel 2026 Intelligence
import requests
import re


GIT_PATHS = [
    "/.git/config", "/.git/HEAD", "/.git/index",
    "/.git/logs/HEAD", "/.git/refs/heads/main",
    "/.git/refs/heads/master", "/.git/refs/heads/develop",
    "/.git/COMMIT_EDITMSG", "/.git/description",
    "/.git/info/refs", "/.git/info/exclude",
    "/.git/packed-refs", "/.git/objects/info/packs",
    "/.git/refs/stash", "/.git/FETCH_HEAD",
    "/.git/ORIG_HEAD", "/.git/refs/remotes/origin/HEAD",
]

VCS_PATHS = [
    ("/.svn/entries", "SVN", "Subversion repo exposto"),
    ("/.svn/wc.db", "SVN_DB", "SVN database exposta"),
    ("/.hg/store/00manifest.i", "MERCURIAL", "Mercurial repo exposto"),
    ("/.hg/hgrc", "MERCURIAL_RC", "Mercurial config exposta"),
    ("/.bzr/branch/last-revision", "BAZAAR", "Bazaar repo exposto"),
    ("/CVS/Root", "CVS_ROOT", "CVS root exposto"),
    ("/CVS/Entries", "CVS_ENTRIES", "CVS entries exposto"),
]

SENSITIVE_PATTERNS = [
    (r'password\s*=', "PASSWORD_IN_GIT"),
    (r'token\s*=', "TOKEN_IN_GIT"),
    (r'url\s*=\s*https?://[^@]+@', "CREDS_IN_REMOTE_URL"),
    (r'aws_access_key', "AWS_KEY_IN_GIT"),
    (r'private[_-]?key', "PRIVATE_KEY_IN_GIT"),
    (r'secret\s*=', "SECRET_IN_GIT"),
    (r'api[_-]?key\s*=', "APIKEY_IN_GIT"),
    (r'github_token', "GITHUB_TOKEN_IN_GIT"),
    (r'smtp_pass', "SMTP_PASS_IN_GIT"),
]


def _probe_git_files(target):
    """Verifica exposição de arquivos .git."""
    vulns = []
    for path in GIT_PATHS:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 5:
                content = resp.text
                is_git = any(k in content for k in
                             ["[core]", "ref:", "PACK", "commit", "[remote",
                              "gitdir", "[branch", "[user"])
                if is_git or path.endswith("HEAD"):
                    vuln = {
                        "tipo": "GIT_FILE_EXPOSED", "path": path,
                        "severidade": "CRITICO", "tamanho": len(content),
                        "amostra": content[:150],
                        "descricao": f"{path} exposto — source code recovery!",
                    }
                    # Check for inline secrets
                    for pattern, label in SENSITIVE_PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE):
                            vuln["secrets_found"] = True
                            vuln["descricao"] += f" Secret: {label}!"
                            break
                    vulns.append(vuln)
        except Exception:
            continue
    return vulns


def _scan_config_secrets(target):
    """Busca segredos no .git/config."""
    vulns = []
    try:
        resp = requests.get(f"http://{target}/.git/config", timeout=5)
        if resp.status_code == 200:
            for pattern, tipo in SENSITIVE_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    vulns.append({
                        "tipo": tipo, "severidade": "CRITICO",
                        "descricao": f"Segredo em .git/config ({tipo})",
                    })
            # Extract remote URLs
            remotes = re.findall(r'url\s*=\s*(.+)', resp.text)
            if remotes:
                vulns.append({
                    "tipo": "GIT_REMOTES_EXPOSED", "severidade": "ALTO",
                    "remotes": [r.strip() for r in remotes[:5]],
                    "descricao": "Remote URLs expostos — repo source disclosed!",
                })
    except Exception:
        pass
    return vulns


def _check_git_log(target):
    """Verifica histórico de commits."""
    vulns = []
    try:
        resp = requests.get(f"http://{target}/.git/logs/HEAD", timeout=5)
        if resp.status_code == 200 and "commit" in resp.text.lower():
            emails = list(set(re.findall(r'<([^>]+@[^>]+)>', resp.text)))[:15]
            commit_count = resp.text.count("\n")
            vulns.append({
                "tipo": "GIT_LOG_EXPOSED", "severidade": "ALTO",
                "emails_developers": emails,
                "commits_visiveis": commit_count,
                "descricao": f"Git log exposto — {len(emails)} emails, {commit_count} commits!",
            })
    except Exception:
        pass
    return vulns


def _check_other_vcs(target):
    """Verifica outros VCS (SVN, Mercurial, Bazaar, CVS)."""
    vulns = []
    for path, vcs_type, desc in VCS_PATHS:
        try:
            resp = requests.get(f"http://{target}{path}", timeout=5)
            if resp.status_code == 200 and len(resp.text) > 5:
                vulns.append({
                    "tipo": f"{vcs_type}_EXPOSED", "path": path,
                    "severidade": "CRITICO",
                    "descricao": f"{desc} — source code recovery!",
                    "amostra": resp.text[:150],
                })
        except Exception:
            continue
    return vulns


def _check_git_objects(target):
    """Tenta baixar objetos git para verificar se é possível clonar."""
    try:
        resp = requests.get(f"http://{target}/.git/objects/info/packs", timeout=5)
        if resp.status_code == 200 and "pack-" in resp.text:
            pack_hash = re.search(r'pack-([a-f0-9]+)\.pack', resp.text)
            if pack_hash:
                return {
                    "tipo": "GIT_PACK_EXPOSED", "severidade": "CRITICO",
                    "pack_hash": pack_hash.group(1),
                    "descricao": "Git pack file acessível — clone completo do repo possível!",
                }
    except Exception:
        pass
    return None


def run(target, ip, open_ports, banners):
    """
    Scanner Git/VCS Exposure 2026-Grade — .git, SVN, Mercurial, CVS.

    Técnicas: 17 .git paths (HEAD/config/index/refs/stash/FETCH_HEAD/
    ORIG_HEAD), 7 VCS alt paths (SVN/Mercurial/Bazaar/CVS),
    9 secret patterns in config, remote URL extraction,
    developer email enumeration, commit counting,
    pack file detection (full clone), inline secret detection.
    """
    _ = (ip, open_ports, banners)
    vulns = []
    vulns.extend(_probe_git_files(target))
    vulns.extend(_scan_config_secrets(target))
    vulns.extend(_check_git_log(target))
    vulns.extend(_check_other_vcs(target))

    pack = _check_git_objects(target)
    if pack:
        vulns.append(pack)

    return {
        "plugin": "git_dumper", "versao": "2026.1",
        "tecnicas": ["git_files", "config_secrets", "git_log",
                      "svn", "mercurial", "bazaar", "cvs", "pack_clone"],
        "resultados": vulns if vulns else "Nenhum VCS exposto",
    }
