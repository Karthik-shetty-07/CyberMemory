import logging
import os
from flask import Flask, jsonify
from backend import db
from backend.routes.memory_routes import memory_bp


def create_app():
    db.init_db()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1 MB request cap
    logging.basicConfig(level=logging.INFO)
    app.register_blueprint(memory_bp, url_prefix="/api/memory")

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"status": "error", "error": "not found"}), 404

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"status": "error", "error": "request too large"}), 413

    return app


if __name__ == "__main__":
    create_app().run(port=8000, debug=os.environ.get("FLASK_DEBUG") == "1")