"""
CyberMemory AI Flask Application.
Provides REST endpoints for incident investigation, feedback retention,
memory exploration, and file upload validation.
"""

import os
import json
from typing import Dict, Any, Optional
from cybermemory.models import AlertInput, AnalystFeedback
from cybermemory.data_loader import IncidentDataLoader
from cybermemory.memory.hindsight_service import HindsightMemoryService
from cybermemory.agent.investigator import IncidentInvestigator
from cybermemory.security.sanitizer import FileUploadValidator
from cybermemory.security.redactor import SafeLogger, SecretRedactor


def create_app(test_config: Optional[Dict[str, Any]] = None):
    try:
        from flask import Flask, request, jsonify, Response  # type: ignore
    except ImportError:
        # Provide lightweight fallback interface if Flask is not installed in current environment
        return None

    app = Flask(__name__)
    logger = SafeLogger("CyberMemoryAPI")

    # Configuration
    if test_config:
        app.config.update(test_config)

    # Initialize Services
    data_loader = IncidentDataLoader()
    memory_service = HindsightMemoryService(
        force_mock=app.config.get("FORCE_MOCK_MEMORY", False),
        mock_persistence_file=app.config.get("MEMORY_PERSISTENCE_FILE")
    )
    investigator = IncidentInvestigator(
        memory_service=memory_service,
        force_mock_llm=app.config.get("FORCE_MOCK_LLM", False)
    )

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Operational-Mode"] = "READ_ONLY_ANALYSIS"
        return response

    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.exception(f"Unhandled API error: {e}")
        # Redact any sensitive internal tokens before returning error
        safe_msg = SecretRedactor.redact_text(str(e))
        return jsonify({
            "status": "error",
            "error_type": type(e).__name__,
            "message": safe_msg,
            "operational_mode": "READ_ONLY_ANALYSIS"
        }), 500

    @app.route("/api/health", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "healthy",
            "service": "CyberMemory AI Investigation Engine",
            "version": "1.0.0",
            "operational_mode": "READ_ONLY_ANALYSIS",
            "hindsight_connected": memory_service.is_live,
            "memory_bank_count": memory_service.count_memories(),
            "llm_backend": "Groq API (openai/gpt-oss-120b)" if investigator.groq_api_key else "Deterministic Heuristics Engine"
        })

    @app.route("/api/investigate", methods=["POST"])
    def investigate():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"status": "error", "message": "Request body must be valid JSON"}), 400

        bank_id = request.args.get("bank_id", memory_service.default_bank_id)
        report = investigator.investigate(data, bank_id=bank_id)
        return jsonify({
            "status": "success",
            "data": report.to_dict()
        })

    @app.route("/api/feedback", methods=["POST"])
    def record_feedback():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"status": "error", "message": "Feedback body must be JSON"}), 400

        required = ["incident_id", "rating", "actual_outcome"]
        for r in required:
            if r not in data:
                return jsonify({"status": "error", "message": f"Missing required field '{r}'"}), 400

        bank_id = request.args.get("bank_id", memory_service.default_bank_id)

        # Store feedback into Hindsight memory
        memory_payload = {
            "incident_id": data["incident_id"],
            "alert_type": data.get("alert_type", "Investigated Incident"),
            "description": data.get("description", "Analyst feedback recorded"),
            "root_cause": data.get("actual_root_cause", "Confirmed by analyst"),
            "remediation": data.get("actual_remediation", "Executed remediation"),
            "final_outcome": data["actual_outcome"],
            "analyst_feedback": {
                "rating": data["rating"],
                "comments": data.get("comments", "")
            },
            "lessons_learned": data.get("lessons_learned", "Analyst confirmed resolution procedure.")
        }

        retain_result = memory_service.retain_incident(memory_payload, bank_id=bank_id)

        return jsonify({
            "status": "success",
            "message": "Analyst feedback retained in Hindsight memory",
            "memory_result": retain_result
        })

    @app.route("/api/incidents", methods=["GET"])
    def list_incidents():
        alert_type = request.args.get("type")
        severity = request.args.get("severity")
        query = request.args.get("q")

        if alert_type:
            results = data_loader.filter_by_type(alert_type)
        elif severity:
            results = data_loader.filter_by_severity(severity)
        elif query:
            results = data_loader.search_text(query)
        else:
            results = data_loader.get_all()

        return jsonify({
            "status": "success",
            "total": len(results),
            "incidents": results
        })

    @app.route("/api/incidents/<incident_id>", methods=["GET"])
    def get_incident(incident_id):
        inc = data_loader.get_by_id(incident_id)
        if not inc:
            return jsonify({"status": "error", "message": f"Incident {incident_id} not found"}), 404
        return jsonify({"status": "success", "incident": inc})

    @app.route("/api/memory/seed", methods=["POST"])
    def seed_memory():
        bank_id = request.args.get("bank_id", memory_service.default_bank_id)
        all_incidents = data_loader.get_all()
        seeded_count = 0
        for inc in all_incidents:
            memory_service.retain_incident(inc, bank_id=bank_id)
            seeded_count += 1

        return jsonify({
            "status": "success",
            "message": f"Successfully seeded {seeded_count} incidents into Hindsight memory bank '{bank_id}'",
            "bank_id": bank_id,
            "total_memories": memory_service.count_memories(bank_id=bank_id)
        })

    @app.route("/api/memory/stats", methods=["GET"])
    def memory_stats():
        bank_id = request.args.get("bank_id", memory_service.default_bank_id)
        return jsonify({
            "status": "success",
            "bank_id": bank_id,
            "total_memories": memory_service.count_memories(bank_id=bank_id),
            "is_live_hindsight": memory_service.is_live,
            "dataset_statistics": data_loader.get_statistics()
        })

    @app.route("/api/upload", methods=["POST"])
    def upload_file():
        if "file" not in request.files:
            return jsonify({"status": "error", "message": "No file part in request"}), 400

        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"status": "error", "message": "No file selected"}), 400

        try:
            clean_filename = FileUploadValidator.validate_filename(file.filename)
            content_bytes = file.read()
            is_valid, msg = FileUploadValidator.validate_file_content(content_bytes, clean_filename)
            if not is_valid:
                return jsonify({"status": "error", "message": f"File rejected: {msg}"}), 400

            return jsonify({
                "status": "success",
                "filename": clean_filename,
                "size_bytes": len(content_bytes),
                "message": "File passed all security and content validation checks"
            })
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    return app


if __name__ == "__main__":
    app = create_app()
    if app:
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
    else:
        print("Flask not installed. Run 'pip install -r requirements.txt' to start API.")
