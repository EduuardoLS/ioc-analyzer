import json
import os
from datetime import datetime

class ReportExporter:
    @staticmethod
    def save_json(ioc_value: str, report_data: dict):
        os.makedirs("data/reports", exist_ok=True)
        filename_safe = ioc_value.replace(".", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = f"data/reports/{filename_safe}_{timestamp}.json"

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        
        print(f"[Sucesso] Relatório salvo em: {filepath}")