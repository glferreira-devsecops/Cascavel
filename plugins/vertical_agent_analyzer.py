# plugins/vertical_agent_analyzer.py
import platform
import subprocess

import psutil


def detect_hardware():
    """Detect hardware to recommend the best local AI model."""
    try:
        ram_gb = psutil.virtual_memory().total / (1024**3)
        os_name = platform.system()
        arch = platform.machine()

        gpu_info = "N/A"
        if os_name == "Linux":
            try:
                # Simplistic check for nvidia gpu
                res = subprocess.run(["nvidia-smi"], capture_output=True, text=True)
                if res.returncode == 0:
                    gpu_info = "NVIDIA GPU Detected"
            except FileNotFoundError:
                pass
        elif os_name == "Darwin":
            if arch == "arm64":
                gpu_info = "Apple Silicon (M-series)"

        return {
            "ram_gb": round(ram_gb, 2),
            "os": os_name,
            "arch": arch,
            "gpu": gpu_info,
        }
    except Exception as e:
        return {"error": str(e)}


def get_ai_recommendation(hw_profile):
    """Provide AI setup instructions based on hardware."""
    if "error" in hw_profile:
        return "Erro ao detectar hardware. Sugerimos usar Groq Cloud API (Llama-3)."

    ram = hw_profile.get("ram_gb", 0)
    os_name = hw_profile.get("os", "Unknown")
    gpu = hw_profile.get("gpu", "N/A")

    cmd = ""
    model = ""

    if os_name == "Linux":
        install_cmd = "curl -fsSL https://ollama.com/install.sh | sh"
    elif os_name == "Darwin":
        install_cmd = "brew install ollama"
    else:
        install_cmd = "Baixe em https://ollama.com/download/windows"

    if ram >= 16 or "Apple Silicon" in gpu or "NVIDIA" in gpu:
        model = "llama3:8b-instruct-q4_K_M"
        cmd = f"ollama run {model}"
    elif ram >= 8:
        model = "phi3:mini-instruct-q4"
        cmd = f"ollama run {model}"
    else:
        return (
            "Hardware modesto detectado (<8GB RAM). Recomendamos fortemente usar APIs Cloud "
            "rápidas e gratuitas como GroqCloud ou TogetherAI (Llama-3) ao invés de rodar localmente."
        )

    return {
        "model_recomendado": model,
        "comando_instalacao": install_cmd,
        "comando_execucao": cmd,
        "nota": "Baixe a IA local para analisar as vulnerabilidades com privacidade total.",
    }


def heuristic_chain_analyzer(target, open_ports, banners):
    """
    Simula uma heurística de Vertical Agent que descobre ataques em cadeia.
    """
    chains = []

    # Exemplo 1: HTTP aberto + possível serviço vulnerável
    if 80 in open_ports or 443 in open_ports:
        chains.append(
            "[Risco Crítico] Porta Web aberta detectada. O agente pode encadear SSRF para ler metadados internos "
            "ou buscar LFI e escalar para RCE via envenenamento de log."
        )

    # Exemplo 2: SSH aberto + FTP
    if 22 in open_ports and 21 in open_ports:
        chains.append(
            "[Risco Crítico] SSH e FTP abertos. O agente investigará se credenciais fracas no FTP "
            "podem ser reusadas no SSH ou se arquivos de chave (id_rsa) estão expostos."
        )

    if not chains:
        chains.append(
            "O agente heurístico não encontrou vetores de encadeamento óbvios nas portas informadas."
        )

    return chains


def run(target, ip, open_ports, banners):
    """
    Motor Vertical AI - Agentic Security.
    Analisa encadeamento de exploits e recomenda IA ideal para o host atual.
    """
    hw_profile = detect_hardware()
    ai_setup = get_ai_recommendation(hw_profile)
    chains = heuristic_chain_analyzer(target, open_ports, banners)

    return {
        "plugin": "vertical_agent_analyzer",
        "resultados": {
            "hardware_detectado": hw_profile,
            "ia_recomendada_setup": ai_setup,
            "analise_encadeamento_heuristico": chains,
        },
    }
