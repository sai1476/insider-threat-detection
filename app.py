from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify, session
import pandas as pd
import os
import uuid
from detect_anomalies import run_detection
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
OUTPUT_PATH = "output/flagged_users.csv"
LOG_FILE = "security_log.txt"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("output", exist_ok=True)

# Live alerts list (kept for dashboard compatibility)
live_alerts = []

# --- Logging function ---
def log_action(action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {action}\n")

# --- Login required decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# --- Login route ---
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == "Admin" and password == "@admin123":
            session["logged_in"] = True
            log_action(f"User '{username}' logged in")
            return redirect(url_for("upload"))
        else:
            error = "Invalid credentials"
            log_action(f"Failed login attempt with username '{username}'")
    return render_template("login.html", error=error)

# --- Logout route ---
@app.route("/logout")
@login_required
def logout():
    username = "admin"
    session.pop("logged_in", None)
    log_action(f"User '{username}' logged out")
    return redirect(url_for("login"))

# --- Upload route ---
ALLOWED_EXTENSIONS = {"csv"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    error = None
    if request.method == "POST":
        if "file" not in request.files:
            error = "No file selected!"
            return render_template("upload.html", error=error)
        file = request.files["file"]
        if file.filename == "":
            error = "No file selected!"
            return render_template("upload.html", error=error)

        if not allowed_file(file.filename):
            error = "Only CSV files are allowed!"
            return render_template("upload.html", error=error)

        # Save file
        filename = f"{uuid.uuid4().hex}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        log_action(f"Uploaded file: {filename}")

        try:
            run_detection(filepath)
        except Exception as e:
            error = f"Error processing file {file.filename}: {e}"
            log_action(error)
            return render_template("upload.html", error=error)

        return redirect(url_for("results"))

    return render_template("upload.html", error=error)

# --- Results dashboard ---
@app.route("/results")
@login_required
def results():
    if not os.path.exists(OUTPUT_PATH):
        return "No results available. Please upload a file first.", 400

    df = pd.read_csv(OUTPUT_PATH)
    total_users = df['user_id'].nunique()
    anomalies = df[df['is_anomaly'] == 1]

    alerts = []
    if (anomalies['data_transferred_MB'] > 1000).any():
        alerts.append("⚠️ High data transfer detected!")
    if (anomalies['files_accessed'] > 100).any():
        alerts.append("⚠️ Excessive file access detected!")
    if (anomalies['usb_inserted'] > 0).any():
        alerts.append("⚠️ USB device usage detected!")

    return render_template(
        "result.html",
        total_users=total_users,
        total_logs=len(df),
        anomalies_count=len(anomalies),
        anomalies=anomalies.to_dict(orient="records"),
        alerts=alerts
    )

# --- Detailed results ---
@app.route("/detailed_results")
@login_required
def detailed_results():
    if not os.path.exists(OUTPUT_PATH):
        return "No results available. Please upload a file first.", 400

    df = pd.read_csv(OUTPUT_PATH)
    return render_template("detailed_results.html", tables=df.to_html(classes="table table-striped", index=False))

# --- Admin logs page ---
@app.route("/admin_logs")
@login_required
def admin_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()
    return render_template("admin_logs.html", logs=logs)

# --- Prevention page ---
@app.route("/prevention")
@login_required
def prevention():
    return render_template("prevention.html")

# --- Live alert API (kept for dashboard compatibility) ---
@app.route("/api/trigger_alert", methods=["POST"])
def trigger_alert():
    msg = request.args.get("msg", "⚠️ Insider Activity Detected!")
    live_alerts.append(msg)
    log_action(f"Live alert triggered: {msg}")
    return jsonify({"status": "ok", "message": msg})

@app.route("/api/get_alerts")
def get_alerts():
    if live_alerts:
        msg = live_alerts.pop(0)
        return jsonify({"alert": msg})
    return jsonify({"alert": None})

# --- Home redirects to login ---
@app.route("/")
def index():
    return render_template("index.html")

# --- Run app (Render-compatible) ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)