# app.py (Flask Backend with Auth, Multi-Project Support, and Styled Login Page)
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
import json
import os
import csv
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace with a secure secret key in production
UPLOAD_FOLDER = "static"
JSON_FILENAME = "gl-sast-report.json"
CSV_FILENAME = "vulnerability-report.csv"
USERNAME = "devops"
PASSWORD = "DevOps@123"  # Replace with a strong password in production

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == USERNAME and password == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.pop('logged_in', None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    project = request.form.get("project")
    if not file or not project:
        return "Missing file or project name", 400

    project_folder = os.path.join(UPLOAD_FOLDER, project)
    os.makedirs(project_folder, exist_ok=True)
    filepath = os.path.join(project_folder, "gl-sast-report.json")
    file.save(filepath)
    return "Uploaded successfully", 200

@app.route("/projects")
@login_required
def list_projects():
    if not os.path.exists(UPLOAD_FOLDER):
        return jsonify([])
    return jsonify([d for d in os.listdir(UPLOAD_FOLDER) if os.path.isdir(os.path.join(UPLOAD_FOLDER, d))])

@app.route("/data/<project>")
@login_required
def get_data(project):
    filepath = os.path.join(UPLOAD_FOLDER, project, "gl-sast-report.json")
    if not os.path.exists(filepath):
        return jsonify({"vulnerabilities": []})

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data)

# ✅ Full working Flask route: download_csv with 11 fields

@app.route("/download_csv/<project>")
@login_required
def download_csv(project):
    filepath = os.path.join(UPLOAD_FOLDER, project, "gl-sast-report.json")
    if not os.path.exists(filepath):
        return "No report available", 404

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # ✅ Final updated headers
    headers = [
        "Name", "Severity", "File", "Line", "Category",
        "CVE", "CWE", "OWASP", "Ref Link",
        "Description", "Remediation"
    ]
    rows = []

    for v in data.get("vulnerabilities", []):
        identifiers = v.get("identifiers", [])
        cwe = next((i.get("value") for i in identifiers if i.get("type") == "cwe"), "N/A")
        owasp = ", ".join(i.get("name", "") for i in identifiers if i.get("type") == "owasp")
        cve = v.get("cve", "N/A")
        ref_links = ", ".join(i.get("url", "") for i in identifiers if i.get("url"))
        description = v.get("description", "").replace("\n", " ").replace("\"", "'").strip()
        remediation = (
            "Avoid user-supplied regular expressions. Use safe patterns or RE2."
            if "RegExp" in description
            else "Refer to the official documentation or CWE/OWASP link."
        )
         # 🔍 Debug output
    print("CVE:", cve)
    print("Ref links:", ref_links)

    rows.append([
            v.get("name", ""),
            v.get("severity", ""),
            v.get("location", {}).get("file", ""),
            v.get("location", {}).get("start_line", ""),
            v.get("category", ""),
            cve,
            f"CWE-{cwe}" if cwe != "N/A" else "N/A",
            owasp or "N/A",
            ref_links or "N/A",
            description,
            remediation
        ])

    # ✅ Save to project folder
    timestamp = datetime.now().strftime("%Y-%m-%d")
    csv_name = f"vulnerability-report-{timestamp}.csv"
    csv_path = os.path.join(UPLOAD_FOLDER, project, csv_name)

    with open(csv_path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    return send_file(csv_path, as_attachment=True)


if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)



# templates/index.html
# (Copy your original HTML and add the following JS logic in the table row creation script):
# Add an event listener in JS like:
# row.addEventListener('click', () => {
#     fetch(`/vulnerability/${vuln.id}`)
#         .then(res => res.json())
#         .then(data => showModal(data));
# });
# Then define a showModal() function to populate a Bootstrap/modal with vulnerability info.
# The modal should display vuln.description, file, line, category, CWE/OWASP links, etc.

# static/
# You don't need to manually add gl-sast-report.json.
# It will be uploaded using the dashboard interface.
