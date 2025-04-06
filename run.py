import os
import json
import subprocess
from datetime import datetime
import requests
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash
import ast

# Configure Flask app.
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"  # Replace with a secure key for production.
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "site.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Model along with your other models.
class CodeReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gpu_id = db.Column(db.Integer, db.ForeignKey("gpu.id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Either code can be pasted or a file can be uploaded.
    code = db.Column(db.Text, nullable=True)
    file_data = db.Column(db.LargeBinary, nullable=True)  # Store file content if uploaded.
    filename = db.Column(db.String(200), nullable=True)     # Original filename.
    status = db.Column(db.String(20), default="pending")  # pending, approved, denied
    submitted_time = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_by = db.Column(db.String(80), nullable=True)
    reviewed_time = db.Column(db.DateTime, nullable=True)

    # Relationships
    gpu = db.relationship("GPU", backref=db.backref("code_reviews", lazy=True))
    client = db.relationship("User")

class UnsafeCodeVisitor(ast.NodeVisitor):
    def __init__(self):
        self.unsafe = False
        self.reason = ""

    def generic_visit(self, node):
        if self.unsafe:
            return  # short-circuit if already unsafe
        super().generic_visit(node)

    def visit_Import(self, node):
        # Disallow dangerous modules.
        dangerous_modules = {"os", "sys", "subprocess", "shutil", "socket", "psutil"}
        for alias in node.names:
            if alias.name.split('.')[0] in dangerous_modules:
                self.unsafe = True
                self.reason = f"Importing module '{alias.name}' is not allowed."
                return
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        # Disallow dangerous imports from modules.
        dangerous_modules = {"os", "sys", "subprocess", "shutil", "socket", "psutil"}
        if node.module and node.module.split('.')[0] in dangerous_modules:
            self.unsafe = True
            self.reason = f"Importing from module '{node.module}' is not allowed."
            return
        self.generic_visit(node)

    def visit_Call(self, node):
        # Disallow dangerous function calls.
        dangerous_functions = {"eval", "exec", "open", "__import__"}
        # Check if the call is to a function with a dangerous name.
        if isinstance(node.func, ast.Name) and node.func.id in dangerous_functions:
            self.unsafe = True
            self.reason = f"Call to function '{node.func.id}' is not allowed."
            return
        # Also, check for attribute calls (e.g. os.system)
        if isinstance(node.func, ast.Attribute):
            # You might check both the attribute name and its parent
            dangerous_attrs = {"system", "popen", "remove", "rmdir", "mkdir", "chdir"}
            if node.func.attr in dangerous_attrs:
                self.unsafe = True
                self.reason = f"Call to method '{node.func.attr}' is not allowed."
                return
        self.generic_visit(node)

def safe_code_check(code):
    """
    Parses the submitted code and checks for dangerous constructs.
    Returns (True, "Code is safe") if safe, otherwise (False, "error message").
    """
    try:
        tree = ast.parse(code)
    except Exception as e:
        return False, f"Code could not be parsed: {str(e)}"
    visitor = UnsafeCodeVisitor()
    visitor.visit(tree)
    if visitor.unsafe:
        return False, visitor.reason
    return True, "Code is safe."

def automated_code_scan(code):
    """
    A stronger automated scan using basic pattern checks.
    This is not bulletproof but checks for several suspicious constructs.
    """
    # You can expand this list as needed.
    suspicious_patterns = [
        "import virus", "eval(", "exec(", "os.system", "subprocess.Popen", "__import__"
    ]
    for pattern in suspicious_patterns:
        if pattern in code:
            return False, f"Suspicious pattern '{pattern}' detected."
    return True, "Code passed automated scan."

# -------------------------------
# Custom Template Filters
# -------------------------------
@app.template_filter('uptime')
def uptime_filter(gpu):
    if not gpu.start_time:
        return "N/A"
    now = datetime.utcnow()
    threshold = 10  # seconds; adjust to your desired threshold
    effective_now = now
    if gpu.connected:
        # If last update is older than threshold, freeze uptime at last_update
        if gpu.last_update is None or (now - gpu.last_update).total_seconds() > threshold:
            effective_now = gpu.last_update if gpu.last_update else now
    else:
        if gpu.disconnect_time:
            effective_now = gpu.disconnect_time
    delta = effective_now - gpu.start_time
    seconds = int(delta.total_seconds())
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"

@app.template_filter('gpu_status')
def gpu_status(gpu):
    # If not connected, and disconnect_time is set and more than 5 minutes ago, mark as Offline.
    threshold = 60  # seconds (5 minutes)
    now = datetime.utcnow()
    if gpu.connected:
        # If no heartbeat or last update is older than the threshold, consider it offline.
        if gpu.last_update is None or (now - gpu.last_update).total_seconds() > threshold:
            return "Unavailable"
        elif gpu.idle:
            return "Idle"
        else:
            return "Active"
    else:
        if gpu.disconnect_time and (now - gpu.disconnect_time).total_seconds() > threshold:
            return "Unavailable"
        return "Disconnected"

# ================================
# Models
# ================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="client")
    active = db.Column(db.Boolean, default=True)  # For banning/restricting users.
    gpus = db.relationship("GPU", backref="host_user", lazy=True)
    requests = db.relationship("GPUAccessRequest", backref="client", lazy=True)

class GPU(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(100), nullable=True)  # Unique GPU identifier.
    name = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(500))
    host_address = db.Column(db.String(50))  # IP address of the GPU agent.
    host_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)  # When attached.
    disconnect_time = db.Column(db.DateTime, nullable=True)  # When disconnected.
    usage_time = db.Column(db.Float, default=0)  # In seconds.
    connected = db.Column(db.Boolean, default=True)  # True: linked; False: stopped.
    idle = db.Column(db.Boolean, default=False)      # True: idle; False: active.
    last_update = db.Column(db.DateTime, nullable=True)
    access_requests = db.relationship("GPUAccessRequest", backref="gpu", lazy=True)

class GPUAccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gpu_id = db.Column(db.Integer, db.ForeignKey("gpu.id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), default="requested")  # requested, approved, denied.
    request_time = db.Column(db.DateTime, default=datetime.utcnow)
    code = db.Column(db.Text, nullable=True)  # Optional code submitted for review.
    verified_by = db.Column(db.String(80), nullable=True)  # Verifier's username.
    verified_time = db.Column(db.DateTime, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================================
# Routes for Authentication
# ================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash("Already logged in.", "info")
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if not user.active:
                flash("Your account has been banned or restricted.", "danger")
                return redirect(url_for("login"))
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        flash("Already logged in.", "info")
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("index"))

# ================================
# GPU Hosting and Request Workflow
# ================================
@app.route("/my_gpu")
@login_required
def my_gpu():
    my_gpus = GPU.query.filter_by(host_user_id=current_user.id).all()
    return render_template("my_gpu.html", gpus=my_gpus)

@app.route("/available_gpus")
@login_required
def available_gpus():
    query = request.args.get("q", "")
    gpus_query = GPU.query.filter(GPU.connected == True,
                                  GPU.idle == False,
                                  GPU.host_user_id != current_user.id)
    if query:
        gpus_query = gpus_query.filter(GPU.name.ilike(f"%{query}%"))
    gpus = gpus_query.all()
    return render_template("available_gpus.html", gpus=gpus, query=query)

@app.route("/request_gpu/<int:gpu_id>", methods=["GET", "POST"])
@login_required
def request_gpu(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    if gpu.host_user_id == current_user.id:
        flash("You already host this GPU.", "info")
        return redirect(url_for("available_gpus"))
    if request.method == "POST":
        # Get code from textarea.
        code = request.form.get("code") or ""
        # If a file is uploaded, read its content.
        if "code_file" in request.files:
            file = request.files["code_file"]
            if file and file.filename != "":
                code = file.read().decode("utf-8")
                # Run automated malware/spyware scan.
                safe, message = automated_code_scan(code)
                if not safe:
                    flash(f"Automated scan failed: {message}", "danger")
                    # Optionally, mark the request as denied automatically.
                    new_req = GPUAccessRequest(
                        gpu_id=gpu_id,
                        client_id=current_user.id,
                        code=code,
                        status="denied"
                    )
                    db.session.add(new_req)
                    db.session.commit()
                    return redirect(url_for("available_gpus"))
        # Check for an existing request with status "requested" or "pending".
        existing = GPUAccessRequest.query.filter(
            GPUAccessRequest.gpu_id == gpu_id,
            GPUAccessRequest.client_id == current_user.id,
            GPUAccessRequest.status.in_(["requested", "pending"])
        ).first()
        if existing:
            flash("You have already submitted a request for this GPU.", "info")
        else:
            new_req = GPUAccessRequest(gpu_id=gpu_id, client_id=current_user.id, code=code)
            db.session.add(new_req)
            db.session.commit()
            flash("GPU access request submitted.", "success")
        return redirect(url_for("available_gpus"))
    return render_template("request_gpu.html", gpu=gpu)

@app.route("/my_requests")
@login_required
def my_requests():
    reqs = GPUAccessRequest.query.filter_by(client_id=current_user.id).all()
    code_reviews = CodeReview.query.filter_by(client_id=current_user.id).all()
    return render_template("my_requests.html", requests=reqs, reviews=code_reviews)

@app.route("/gpu/<int:gpu_id>/requests")
@login_required
def gpu_requests(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    if gpu.host_user_id != current_user.id and current_user.role not in ["admin", "moderator"]:
        flash("Unauthorized to view requests for this GPU.", "danger")
        return redirect(url_for("index"))
    reqs = GPUAccessRequest.query.filter_by(gpu_id=gpu_id).all()
    return render_template("gpu_requests.html", gpu=gpu, requests=reqs)

@app.route("/approve_request/<int:req_id>")
@login_required
def approve_request(req_id):
    req_obj = GPUAccessRequest.query.get_or_404(req_id)
    gpu = GPU.query.get(req_obj.gpu_id)
    if not (current_user.role in ["admin", "moderator"] or current_user.id == gpu.host_user_id):
        flash("Unauthorized to approve requests.", "danger")
        return redirect(url_for("index"))
    req_obj.status = "approved"
    req_obj.verified_by = current_user.username
    req_obj.verified_time = datetime.utcnow()
    db.session.commit()
    flash(f"Request {req_obj.id} approved.", "success")
    return redirect(url_for("gpu_requests", gpu_id=req_obj.gpu_id))

@app.route("/deny_request/<int:req_id>")
@login_required
def deny_request(req_id):
    req_obj = GPUAccessRequest.query.get_or_404(req_id)
    gpu = GPU.query.get(req_obj.gpu_id)
    if not (current_user.role in ["admin", "moderator"] or current_user.id == gpu.host_user_id):
        flash("Unauthorized to deny requests.", "danger")
        return redirect(url_for("index"))
    req_obj.status = "denied"
    req_obj.verified_by = current_user.username
    req_obj.verified_time = datetime.utcnow()
    db.session.commit()
    flash(f"Request {req_obj.id} denied.", "info")
    return redirect(url_for("gpu_requests", gpu_id=req_obj.gpu_id))

# Endpoint for GPU owner or admin to revoke an approved access request.
@app.route("/revoke_access/<int:req_id>")
@login_required
def revoke_access(req_id):
    req_obj = GPUAccessRequest.query.get_or_404(req_id)
    gpu = GPU.query.get(req_obj.gpu_id)
    # Only allow if the current user is the GPU owner or admin.
    if not (current_user.role == "admin" or current_user.id == gpu.host_user_id):
        flash("Unauthorized to revoke access.", "danger")
        return redirect(url_for("index"))
    if req_obj.status != "approved":
        flash("Only approved requests can be revoked.", "info")
    else:
        req_obj.status = "revoked"
        req_obj.verified_by = current_user.username
        req_obj.verified_time = datetime.utcnow()
        db.session.commit()
        flash("Access revoked successfully.", "success")
    return redirect(url_for("gpu_requests", gpu_id=gpu.id))

# Endpoint for a client to cancel or give up their access request voluntarily.
@app.route("/cancel_request/<int:req_id>")
@login_required
def cancel_request(req_id):
    req_obj = GPUAccessRequest.query.get_or_404(req_id)
    # Only allow the client who submitted the request to cancel it.
    if current_user.id != req_obj.client_id:
        flash("Unauthorized to cancel this request.", "danger")
        return redirect(url_for("index"))
    # Allow cancellation if the request is not already approved
    # (If already approved, the client may need to contact the GPU owner/admin to revoke access.)
    if req_obj.status in ["requested", "pending", "revoked"]:
        req_obj.status = "cancelled"
        db.session.commit()
        flash("Your access request has been cancelled.", "success")
    else:
        flash("Approved requests cannot be cancelled directly. Please contact the GPU owner.", "warning")
    return redirect(url_for("my_requests"))

# Endpoints for approving and denying code review requests (only GPU owner or admin can do this)
@app.route("/approve_review/<int:review_id>")
@login_required
def approve_review(review_id):
    review = CodeReview.query.get_or_404(review_id)
    gpu = GPU.query.get(review.gpu_id)
    if current_user.id != gpu.host_user_id and current_user.role != "admin":
        flash("Unauthorized to approve code reviews.", "danger")
        return redirect(url_for("gpu_detail", gpu_id=gpu.id))
    review.status = "approved"
    review.reviewed_by = current_user.username
    review.reviewed_time = datetime.utcnow()
    db.session.commit()
    flash(f"Code review {review.id} approved.", "success")
    return redirect(url_for("code_reviews", gpu_id=gpu.id))

@app.route("/deny_review/<int:review_id>")
@login_required
def deny_review(review_id):
    review = CodeReview.query.get_or_404(review_id)
    gpu = GPU.query.get(review.gpu_id)
    if current_user.id != gpu.host_user_id and current_user.role != "admin":
        flash("Unauthorized to deny code reviews.", "danger")
        return redirect(url_for("gpu_detail", gpu_id=gpu.id))
    review.status = "denied"
    review.reviewed_by = current_user.username
    review.reviewed_time = datetime.utcnow()
    db.session.commit()
    flash(f"Code review {review.id} denied.", "info")
    return redirect(url_for("code_reviews", gpu_id=gpu.id))

# Route to view code review requests for a GPU (accessible by GPU owner or admin)
@app.route("/gpu/<int:gpu_id>/code_reviews")
@login_required
def code_reviews(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    if gpu.host_user_id != current_user.id and current_user.role != "admin":
        flash("Unauthorized to view code reviews for this GPU.", "danger")
        return redirect(url_for("gpu_detail", gpu_id=gpu_id))
    reviews = CodeReview.query.filter_by(gpu_id=gpu_id).all()
    return render_template("code_reviews.html", gpu=gpu, reviews=reviews)

# Endpoint for submitting code review
@app.route("/submit_code_review/<int:gpu_id>", methods=["POST"])
@login_required
def submit_code_review(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    # Only non-owners submit for review.
    if current_user.id == gpu.host_user_id:
        return jsonify({"error": "Owners should run code directly."}), 403
    data = request.get_json()
    code = data.get("code")
    if not code:
        return jsonify({"error": "No code provided."}), 400
    # Run the automated safety check
    is_safe, message = safe_code_check(code)
    if not is_safe:
        # Automatically reject if unsafe.
        return jsonify({"error": f"Code rejected: {message}"}), 400
    # Create a new code review record (you'll need a new model for this).
    new_review = CodeReview(gpu_id=gpu_id, client_id=current_user.id, code=code, status="pending")
    db.session.add(new_review)
    db.session.commit()
    return jsonify({"message": "Code submitted for review."}), 200

@app.route("/download_review/<int:review_id>")
@login_required
def download_review(review_id):
    review = CodeReview.query.get_or_404(review_id)
    gpu = GPU.query.get(review.gpu_id)
    # Only allow the client who submitted or the GPU owner/admin to download
    if current_user.id != review.client_id and current_user.id != gpu.host_user_id and current_user.role != "admin":
        flash("Unauthorized to download this file.", "danger")
        return redirect(url_for("my_requests"))
    if review.status != "approved":
        flash("This review has not been approved yet.", "warning")
        return redirect(url_for("my_requests"))
    if not review.file_data:
        flash("No file available for this review.", "info")
        return redirect(url_for("my_requests"))
    return send_file(io.BytesIO(review.file_data), as_attachment=True, attachment_filename=review.filename)

@app.route("/run_reviewed_code/<int:review_id>")
@login_required
def run_reviewed_code(review_id):
    review = CodeReview.query.get_or_404(review_id)
    gpu = GPU.query.get(review.gpu_id)
    # Only allow the client who submitted the review to run it (or possibly allow owner/admin to trigger)
    if current_user.id != review.client_id and current_user.id != gpu.host_user_id and current_user.role != "admin":
        flash("Unauthorized to run this reviewed code.", "danger")
        return redirect(url_for("my_requests"))
    if review.status != "approved":
        flash("This code review has not been approved.", "warning")
        return redirect(url_for("my_requests"))
    # Use file_data if available; otherwise, use the code text.
    if review.file_data:
        code = review.file_data.decode("utf-8")
    else:
        code = review.code
    if not code:
        flash("No code available to run.", "warning")
        return redirect(url_for("my_requests"))
    # Forward the code to the execution endpoint.
    execution_url = f"http://{gpu.host_address}:6000/execute_code"
    try:
        r = requests.post(execution_url, json={"code": code})
        if r.status_code == 200:
            output = r.json().get("output")
            flash(f"Code executed successfully: {output}", "success")
        else:
            flash(f"Failed to execute code: {r.json().get('error')}", "danger")
    except Exception as e:
        flash(f"Error connecting to GPU host: {str(e)}", "danger")
    return redirect(url_for("my_requests"))

@app.route("/full_editor/run_review/<int:review_id>")
@login_required
def full_editor_run_review(review_id):
    review = CodeReview.query.get_or_404(review_id)
    gpu = GPU.query.get(review.gpu_id)
    if current_user.id != review.client_id and current_user.id != gpu.host_user_id and current_user.role != "admin":
        flash("Unauthorized to run this reviewed code.", "danger")
        return redirect(url_for("my_requests"))
    if review.status != "approved":
        flash("This code review has not been approved.", "warning")
        return redirect(url_for("my_requests"))
    # Load approved code from file_data if available, else from code.
    preloaded_code = review.file_data.decode("utf-8") if review.file_data else review.code
    return render_template("full_code_editor.html", gpu=gpu, preloaded_code=preloaded_code, review=review)

@app.route("/gpu_status_data/<int:gpu_id>")
@login_required
def gpu_status_data(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    data = {
        "status": gpu_status(gpu),  # using your custom filter function directly
        "uptime": uptime_filter(gpu)
    }
    return jsonify(data)

@app.route("/full_editor/<int:gpu_id>")
@login_required
def full_editor(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    # Allow GPU owner always.
    if current_user.id != gpu.host_user_id:
        # For non-owners, require an approved request.
        approved_req = GPUAccessRequest.query.filter_by(
            gpu_id=gpu_id,
            client_id=current_user.id,
            status="approved"
        ).first()
        if not approved_req:
            flash("Access not approved. You do not have an approved request for this GPU.", "danger")
            return redirect(url_for("gpu_detail", gpu_id=gpu_id))
    if not gpu.connected or gpu.idle:
        flash("GPU is not available for code execution.", "danger")
        return redirect(url_for("gpu_detail", gpu_id=gpu_id))
    return render_template("full_code_editor.html", gpu=gpu)

# ================================
# Admin Dashboard (for admin)
# ================================
@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for("index"))
    users = User.query.all()
    gpus = GPU.query.all()
    return render_template("admin.html", users=users, gpus=gpus)

@app.route("/admin/promote/<int:user_id>")
@login_required
def promote_user(user_id):
    if current_user.role != "admin":
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for("index"))
    user = User.query.get_or_404(user_id)
    if user.role == "client":
        user.role = "moderator"
        db.session.commit()
        flash(f"User {user.username} promoted to moderator.", "success")
    else:
        flash(f"User {user.username} cannot be promoted.", "danger")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/demote/<int:user_id>")
@login_required
def demote_user(user_id):
    if current_user.role != "admin":
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for("index"))
    user = User.query.get_or_404(user_id)
    if user.role == "moderator":
        user.role = "client"
        db.session.commit()
        flash(f"User {user.username} demoted to client.", "success")
    else:
        flash("User cannot be demoted.", "danger")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/ban/<int:user_id>")
@login_required
def ban_user(user_id):
    if current_user.role != "admin":
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for("index"))
    if current_user.id == user_id:
        flash("You cannot ban yourself.", "danger")
        return redirect(url_for("admin_dashboard"))
    user = User.query.get_or_404(user_id)
    user.active = False
    db.session.commit()
    flash(f"User {user.username} banned.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/client_history/<int:client_id>")
@login_required
def client_history(client_id):
    if current_user.role != "admin":
        flash("Unauthorized to view client history.", "danger")
        return redirect(url_for("index"))
    reqs = GPUAccessRequest.query.filter_by(client_id=client_id).filter(
        GPUAccessRequest.status.in_(["approved", "denied"])
    ).all()
    return render_template("client_history.html", requests=reqs)

# ================================
# GPU Detail & Remote Code Execution
# ================================
@app.route("/gpu/<int:gpu_id>")
@login_required
def gpu_detail(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    return render_template("gpu_detail.html", gpu=gpu)

@app.route("/api/execute_code/<int:gpu_id>", methods=["POST"])
@login_required
def api_execute_code(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)

    # If the current user is not the GPU owner, enforce access and code length restrictions.
    if current_user.id != gpu.host_user_id:
        # Ensure the user has an approved access request.
        approved_req = GPUAccessRequest.query.filter_by(
            gpu_id=gpu_id,
            client_id=current_user.id,
            status="approved"
        ).first()
        if not approved_req:
            return jsonify({"error": "Access not approved. You do not have an approved request for this GPU."}), 403

        # Get the code from the request.
        data = request.get_json()
        code = data.get("code")
        if not code:
            return jsonify({"error": "No code provided"}), 400

        # Count the number of lines in the submitted code.
        line_count = len(code.strip().splitlines())
        # If code is 50 lines or more, reject immediate execution.
        if line_count >= 50:
            return jsonify({"error": "Code exceeds the allowed immediate execution limit (50 lines). Please submit your code for review."}), 400

    # For GPU owners, no line count restrictions apply.
    # At this point, proceed with common checks.
    if not gpu.connected:
        return jsonify({"error": "GPU is disconnected"}), 400
    if gpu.idle:
        return jsonify({"error": "GPU is idle; cannot execute code"}), 400

    data = request.get_json()
    code = data.get("code")
    if not code:
        return jsonify({"error": "No code provided"}), 400

    # Only perform safety check for non-owners.
    if current_user.id != gpu.host_user_id:
        is_safe, message = safe_code_check(code)
        if not is_safe:
            return jsonify({"error": f"Unsafe code detected: {message}"}), 400

    if not gpu.host_address:
        return jsonify({"error": "GPU host address not available"}), 400

    execution_url = f"http://{gpu.host_address}:6000/execute_code"
    try:
        r = requests.post(execution_url, json={"code": code})
        if r.status_code == 200:
            output = r.json().get("output")
            return jsonify({"message": "Code executed", "output": output}), 200
        else:
            return jsonify({"error": "Failed to execute code on host", "details": r.json()}), 400
    except Exception as e:
        return jsonify({"error": "Error connecting to GPU host", "details": str(e)}), 500


# ================================
# GPU Connection Management Endpoints
# ================================
@app.route("/disconnect_gpu/<int:gpu_id>")
@login_required
def disconnect_gpu(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    if current_user.role != "admin" and gpu.host_user_id != current_user.id:
        flash("Unauthorized to disconnect GPU.", "danger")
        return redirect(url_for("index"))
    if not gpu.connected:
        flash("GPU is already disconnected.", "info")
    else:
        gpu.connected = False
        gpu.disconnect_time = datetime.utcnow()
        db.session.commit()
        flash("GPU stopped successfully.", "success")
        try:
            disconnect_url = f"http://{gpu.host_address}:6000/update_connection"
            requests.post(disconnect_url, json={"connected": False})
        except Exception as e:
            print("Failed to update GPU execution agent state:", e)
    return redirect(url_for("gpu_detail", gpu_id=gpu_id))

@app.route("/reconnect_gpu/<int:gpu_id>")
@login_required
def reconnect_gpu(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    if current_user.role != "admin" and gpu.host_user_id != current_user.id:
        flash("Unauthorized to reconnect GPU.", "danger")
        return redirect(url_for("index"))
    if gpu.connected:
        flash("GPU is already connected.", "info")
    else:
        gpu.connected = True
        # Preserve the idle flag.
        gpu.disconnect_time = None
        db.session.commit()
        flash("GPU reconnected successfully.", "success")
        try:
            reconnect_url = f"http://{gpu.host_address}:6000/update_connection"
            requests.post(reconnect_url, json={"connected": True})
        except Exception as e:
            print("Failed to update GPU execution agent state:", e)
    return redirect(url_for("gpu_detail", gpu_id=gpu_id))

@app.route("/set_idle_gpu/<int:gpu_id>")
@login_required
def set_idle_gpu(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    if gpu.host_user_id != current_user.id:
        flash("Only the GPU owner can set it to idle.", "danger")
        return redirect(url_for("gpu_detail", gpu_id=gpu_id))
    if not gpu.connected:
        flash("GPU is not connected.", "danger")
    else:
        gpu.idle = True
        db.session.commit()
        flash("GPU set to idle.", "success")
    return redirect(url_for("gpu_detail", gpu_id=gpu_id))

@app.route("/set_active_gpu/<int:gpu_id>")
@login_required
def set_active_gpu(gpu_id):
    gpu = GPU.query.get_or_404(gpu_id)
    if gpu.host_user_id != current_user.id:
        flash("Only the GPU owner can set it active.", "danger")
        return redirect(url_for("gpu_detail", gpu_id=gpu_id))
    if not gpu.connected:
        flash("GPU is not connected.", "danger")
    else:
        gpu.idle = False
        db.session.commit()
        flash("GPU set to active.", "success")
    return redirect(url_for("gpu_detail", gpu_id=gpu_id))

# ================================
# API Endpoint: Register GPU (with reconnection logic)
# ================================
@app.route("/api/register_gpu", methods=["POST"])
def api_register_gpu():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    gpu_info = data.get("gpu_info")
    if not username or not password or not gpu_info:
        return jsonify({"error": "Missing username, password, or gpu_info"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 403
    gpu_details_json = json.dumps(gpu_info)
    host_addr = gpu_info.get("host_address", "")
    gpu_uuid = gpu_info.get("uuid")
    if gpu_uuid:
        existing_gpu = GPU.query.filter_by(host_user_id=user.id, uuid=gpu_uuid).first()
        if existing_gpu:
            existing_gpu.connected = True
            # Preserve the idle state.
            existing_gpu.host_address = host_addr
            existing_gpu.details = gpu_details_json
            existing_gpu.disconnect_time = None
            db.session.commit()
            return jsonify({"message": "GPU reconnected successfully", "gpu_id": existing_gpu.id}), 200
    new_gpu = GPU(
        uuid=gpu_uuid,
        name=gpu_info.get("name", "Unnamed GPU"),
        details=gpu_details_json,
        host_user_id=user.id,
        host_address=host_addr,
        start_time=datetime.utcnow(),
        usage_time=0,
        connected=True,
        idle=False,
    )
    db.session.add(new_gpu)
    db.session.commit()
    return jsonify({"message": "GPU registered successfully", "gpu_id": new_gpu.id}), 200

# ================================
# API Endpoint: Update GPU Stats
# ================================
@app.route("/api/update_gpu_stats", methods=["POST"])
def api_update_gpu_stats():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    gpu_id = data.get("gpu_id")
    usage_time = data.get("usage_time")
    if not username or not password or not gpu_id or usage_time is None:
        return jsonify({"error": "Missing parameters"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 403
    gpu = GPU.query.get(gpu_id)
    if not gpu or gpu.host_user_id != user.id:
        return jsonify({"error": "GPU not found or unauthorized"}), 404
    gpu.usage_time = usage_time
    gpu.last_update = datetime.utcnow()  # heartbeat timestamp.
    db.session.commit()
    return jsonify({"message": "GPU stats updated"}), 200

# ================================
# Application Startup
# ================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Create default admin if not present.
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                password=generate_password_hash("adminpass"),
                role="admin",
            )
            db.session.add(admin_user)
            db.session.commit()
    app.run(host="0.0.0.0", port=5000, debug=True)
