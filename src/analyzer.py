class IOCAnalyzer:
    @staticmethod
    def parse_vt_response(response_json: dict, ioc_type: str):
        try:
            attributes = response_json.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            reputation = attributes.get("reputation", 0)

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            if malicious > 0:
                risk = "Alto Risco / Malicioso"
            elif suspicious > 0:
                risk = "Suspeito"
            elif malicious == 0 and suspicious == 0 and (harmless > 0 or undetected > 0):
                risk = "Baixo Risco / Limpo"
            else:
                risk = "Desconhecido / Não Encontrado"

            return {
                "risk": risk,
                "stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected
                },
                "reputation": reputation
            }
        except Exception:
            return {
                "risk": "Desconhecido / Não Encontrado",
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "reputation": 0
            }