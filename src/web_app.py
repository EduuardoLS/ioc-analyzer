from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

from validators import validate_ip, validate_domain, validate_sha256
from virustotal import VirusTotalClient
from analyzer import IOCAnalyzer
from database import DatabaseManager
from report import ReportExporter

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

vt_client = VirusTotalClient()
db = DatabaseManager()

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json
    if not data:
        return jsonify({"error": "Dados inválidos ou ausentes."}), 400

    ioc_type = data.get('type')
    ioc_value = data.get('value')

    is_valid = False
    if ioc_type == 'ip':
        is_valid = validate_ip(ioc_value)
    elif ioc_type == 'domain':
        is_valid = validate_domain(ioc_value)
    elif ioc_type == 'hash':
        is_valid = validate_sha256(ioc_value)

    if not is_valid:
        return jsonify({"error": "IOC inválido para o tipo selecionado."}), 400

    try:
        if ioc_type == 'ip':
            res = vt_client.query_ip(ioc_value)
        elif ioc_type == 'domain':
            res = vt_client.query_domain(ioc_value)
        else:
            res = vt_client.query_hash(ioc_value)
    except Exception as e:
        return jsonify({"error": f"Erro de comunicação com a API: {str(e)}"}), 500

    if not res or isinstance(res, dict) and "error" in res:
        return jsonify({
            "risk": "Desconhecido / Não Encontrado",
            "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
            "reputation": 0
        }), 200

    processed = IOCAnalyzer.parse_vt_response(res, ioc_type)
    
    try:
        db.save_analysis(ioc_value, ioc_type, processed["risk"], res)
        ReportExporter.save_json(ioc_value, res)
    except Exception:
        pass

    return jsonify(processed)

if __name__ == '__main__':
    app.run(debug=True, port=5000)