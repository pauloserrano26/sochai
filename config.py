import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # API Keys principais
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    
    # Gmail Configuration
    GMAIL_CREDENTIALS_FILE = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    GMAIL_TOKEN_FILE = os.getenv("GMAIL_TOKEN")
    
    # SOC Email Configuration
    SOC_EMAIL_RECIPIENT = os.getenv("SOC_EMAIL_RECIPIENT")
    SOC_EMAIL_SENDER = os.getenv("SOC_EMAIL_SENDER")
    
    # APIs opcionales para Threat Intelligence
    # ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    # URLVOID_API_KEY = os.getenv("URLVOID_API_KEY")
    
    # Configuração do SOC
    WEBHOOK_PORT = 8000
    DASHBOARD_PORT = 8501

    # Database (SQLite — path relativo ao projeto)
    DATABASE_URL = "sqlite:///soc_database.db"

    # HITL SLA defaults (minutos)
    HITL_SLA_CRITICAL = 15
    HITL_SLA_HIGH = 30
    HITL_SLA_NORMAL = 60

    # Validação de configuração — aviso sem bloquear arranque
    @classmethod
    def validate_required_config(cls):
        optional_llm = [
            ("OPENAI_API_KEY", cls.OPENAI_API_KEY),
            ("TAVILY_API_KEY", cls.TAVILY_API_KEY),
            ("VIRUSTOTAL_API_KEY", cls.VIRUSTOTAL_API_KEY),
        ]
        missing = [k for k, v in optional_llm if not v]
        if missing:
            print(f"[AVISO] Chaves em falta (pipeline LLM desativado): {', '.join(missing)}")
        return True

    @classmethod
    def llm_available(cls) -> bool:
        return bool(cls.OPENAI_API_KEY)

    @classmethod
    def gmail_available(cls) -> bool:
        return bool(cls.GMAIL_TOKEN_FILE and cls.GMAIL_CREDENTIALS_FILE)
    
config = Config()