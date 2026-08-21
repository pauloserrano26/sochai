import vt
from langchain.tools import tool
from config import config
from datetime import datetime

# ── TavilySearch (opcional — só necessário para pipeline LLM) ──────────────
search_tool = None
if config.TAVILY_API_KEY:
    try:
        from langchain_tavily import TavilySearch
        search_tool = TavilySearch(max_results=3, api_key=config.TAVILY_API_KEY)
    except Exception as e:
        print(f"[AVISO] TavilySearch nao disponivel: {e}")

# ── Gmail (opcional) ────────────────────────────────────────────────────────
gmail_tools = []
if config.GMAIL_TOKEN_FILE and config.GMAIL_CREDENTIALS_FILE:
    try:
        from langchain_community.agent_toolkits import GmailToolkit
        from langchain_community.tools.gmail.utils import (
            get_gmail_credentials, build_resource_service,
        )
        creds = get_gmail_credentials(
            token_file=config.GMAIL_TOKEN_FILE,
            client_secrets_file=config.GMAIL_CREDENTIALS_FILE,
            scopes=["https://mail.google.com/"],
        )
        gmail_toolkit = GmailToolkit(api_resource=build_resource_service(credentials=creds))
        gmail_tools = gmail_toolkit.get_tools()
        print("[OK] Gmail configurado")
    except Exception as e:
        print(f"[AVISO] Gmail nao configurado: {e}")
else:
    print("[AVISO] Credenciais Gmail nao definidas — notificacoes por email desativadas")

# ── VirusTotal ──────────────────────────────────────────────────────────────
@tool
def virustotal_checker(indicator: str, indicator_type: str) -> str:
    """Analisa URLs, IPs e hashes usando a API do VirusTotal.

    Args:
        indicator: URL, IP ou hash a analisar.
        indicator_type: 'url', 'ip' ou 'hash'
    """
    if not config.VIRUSTOTAL_API_KEY:
        return "VirusTotal nao configurado (VIRUSTOTAL_API_KEY em falta no .env)"
    try:
        with vt.Client(config.VIRUSTOTAL_API_KEY) as client:
            if indicator_type == "url":
                url_id = vt.url_id(indicator)
                analysis = client.get_object(f"/urls/{url_id}")
            elif indicator_type == "ip":
                analysis = client.get_object(f"/ip-addresses/{indicator}")
            elif indicator_type == "hash":
                analysis = client.get_object(f"/files/{indicator}")
            else:
                return f"Tipo nao suportado: {indicator_type}"

            stats = analysis.last_analysis_stats
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if malicious > 5:
                threat_level = "MALICIOSO"
            elif malicious > 0 or suspicious > 3:
                threat_level = "SUSPEITO"
            else:
                threat_level = "LIMPO"

            return (
                f"ANALISE VIRUSTOTAL:\n"
                f"Indicador: {indicator}\n"
                f"Detecoes: {malicious}/{total} maliciosas, {suspicious}/{total} suspeitas\n"
                f"Classificacao: {threat_level}\n"
                f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
    except Exception as e:
        return f"Erro VirusTotal: {str(e)}"


# Lista de ferramentas (apenas as disponiveis)
all_tools = ([search_tool] if search_tool else []) + [virustotal_checker] + gmail_tools