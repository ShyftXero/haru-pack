import os
from flask import Flask, render_template, jsonify

def create_app():
    app = Flask(__name__)  # root_path = this package dir -> templates/ & static/ found regardless of cwd

    @app.route("/")
    def index():
        # demonstrate the three roots reaching the template
        return render_template(
            "index.html",
            cwd=os.getcwd(),
            exe_dir=os.environ.get("HARUPACK_EXE_DIR", "(unset)"),
            stage=os.environ.get("HARUPACK_STAGE", "(unset)"),
        )

    @app.route("/api/ping")
    def ping():
        return jsonify(ok=True, msg="pong from packaged flask")

    return app
