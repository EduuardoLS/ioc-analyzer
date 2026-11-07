import os 
import requests
from dotenv import load_dotenv

load_dotenv ()

class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    def _get(self, endpoint: str):
        url = f"{self.base_url}/{endpoint}"

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            
            elif response.status_code == 401:
                print("[ERROR] Chave de API do VirusTotal invalida")

            elif response.status_code == 429:
                print("[ERROR] Limite de requisições exedidas (Rate Limited)")

            else:
                print(f"[ERROR] Falha na consulta. Código HTTP: {response.status_code}")
                

        except requests.exceptions.RequestException as e:
            print(f"[Erro de conexão]: {e} ")

        return None

    def query_ip(self, ip: str):
        return self._get(f"ip_addresss/{ip}")

    def query_domain(self, domain: str):
        return self._get(f"domains/{domain}")

    def query_hash(self, fiel_hash: str):
        return self._get(f"files/{fiel_hash}")