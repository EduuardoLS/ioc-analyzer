import sys
import os
from validators import validate_ip, validate_domain, validate_sha256
from virustotal import VirusTotalClient
from analyzer import IOCAnalyzer
from database import DatabaseManager
from report import ReportExporter

def menu():
    vt_client = VirusTotalClient()
    db = DatabaseManager()

    while True:
        print("\n=== ANALISADOR DE IOCs (Threat Intelligence) ===")
        print("1. Analisar Endereço IP")
        print("2. Analisar Domínio")
        print("3. Analisar Hash SHA-256")
        print("4. Ver Histórico de Análises")
        print("5. Sair")

        choice = input("\nEscolha uma opção:").strip()

        if choice == "1":
            ip = input("Digiteo IP:").strip()
            if not validate_ip(ip):
                print("[ERROR] Endereço de IP inválido")
                continue
            res = vt_client.query_ip(ip)
            processed = IOCAnalyzer.parse_vt_response(res, "IP")
            print(f"Resultado: Risco -> {processed['risk']} | Estatísticas -> {processed['stats']}")
            db.save_analysis(ip, "IP", processed["risk"], res)
            ReportExporter.save_json(ip, res)

        elif choice == "2":
            domain = input("Digite o Domínio: ").strip()
            if not validate_domain(domain):
                print("[ERROR] Domínio inválido")
                continue
            res = vt_client.query_domain(domain)
            processed = IOCAnalyzer.parse_vt_response(res, "Domain")
            print(f"Resultado: Risco -> {processed['risk']} | Estatísticas -> {processed['stats']}")
            db.save_analysis(domain, "Domain", processed["risk"], res)
            ReportExporter.save_json(domain, res)

        elif choice == "3":
            file_hash = input("Digite o Hash SHA-256:").strip()
            if not validate_sha256(file_hash):
                print("[ERROR] Hash SHA-256 inválido")
                continue
            res = vt_client.query_hash(file_hash)
            processed = IOCAnalyzer.parse_vt_response(res, "Hash")
            print(f"Resultado: Risco -> {processed['risk']} | Estatísticas -> {processed['stats']}")
            db.save_analysis(file_hash, "Hash", processed["risk"], res)
            ReportExporter.save_json(file_hash, res)

        elif choice == "4":
            history = db.get_history()
            print("\n--- HISTÓRICO DE ANÁLISES ---")
            for row in history:
                print(f"ID: {row[0]} | Alvo: {row[1]} | Tipo: {row[2]} | Risco: {row[3]} | Data: {row[4]}")

        elif choice == "5":
            print("Saindo...")
            sys.exit(0)
        else:
            print("[Erro] Opção inválida.")

if __name__ == "__main__":
    menu()