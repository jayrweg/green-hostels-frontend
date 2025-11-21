import uuid
import os
import secrets
from mimetypes import guess_type
from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase_client import supabase
import bcrypt
from datetime import datetime
from functools import wraps
from flask import abort
from flask import request
from tenant_routes import tenant_bp  # Update this import
from collections import defaultdict



app = Flask(__name__)
# Secret key from environment (fallback kept for dev only)
app.secret_key = os.getenv("SECRET_KEY", "super_secret_key")

# Session security settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 8  # 8 hours
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB uploads

app.register_blueprint(tenant_bp)
app.jinja_env.globals.update(request=request)


# ---------- Jinja Filters ----------
def format_tsh(value):
    try:
        num = float(value or 0)
        return f"TSH {num:,.2f}"
    except Exception:
        return value

def month_name(month_num):
    months = ['', 'January', 'February', 'March', 'April', 'May', 'June',
              'July', 'August', 'September', 'October', 'November', 'December']
    try:
        return months[int(month_num)]
    except (ValueError, IndexError):
        return str(month_num)

app.jinja_env.filters['tsh'] = format_tsh
app.jinja_env.filters['month_name'] = month_name

# Inject CSRF token into templates
@app.context_processor
def inject_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return {'csrf_token': token}

def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == 'POST':
            form_token = request.form.get('csrf_token')
            if not form_token or form_token != session.get('csrf_token'):
                flash('Invalid or missing CSRF token.', 'error')
                return redirect(request.referrer or url_for('home'))
        return view(*args, **kwargs)
    return wrapped

def is_superadmin():
    return "user" in session and session["user"].get("role") == "superadmin"

def superadmin_only(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_superadmin():
            # You can also flash+redirect if you prefer
            return redirect(url_for("admin_dashboard"))
        return view(*args, **kwargs)
    return wrapped


def is_admin_or_superadmin() -> bool:
    return "user" in session and session["user"].get("role") in ["admin", "superadmin"]


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_admin_or_superadmin():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped



BUCKET_NAME = "contracts"
ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}
ALLOWED_MIME_TYPES = {
    "pdf": "application/pdf",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
}


# ---------- Helpers ----------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_to_supabase_bucket(file_storage) -> str | None:
    """
    Upload to Supabase Storage with overwrite allowed (upsert).
    Returns the public URL or None.
    """
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        return None

    ext = file_storage.filename.rsplit(".", 1)[-1].lower()
    unique_filename = f"{uuid.uuid4()}.{ext}"
    path_in_bucket = f"contracts/{unique_filename}"

    file_bytes = file_storage.read()

    # derive a mimetype (fallback to octet-stream)
    mimetype, _ = guess_type(file_storage.filename)
    if not mimetype:
        mimetype = "application/octet-stream"

    # cross-check mimetype against extension
    expected_mime = ALLOWED_MIME_TYPES.get(ext)
    if expected_mime and expected_mime != mimetype and not mimetype.startswith("image/"):
        return None

    # IMPORTANT: pass options as dict with string values
    supabase.storage.from_(BUCKET_NAME).upload(
        path_in_bucket,
        file_bytes,
        {
            "content-type": mimetype,
            "upsert": "true"      # <= make sure it's a *string*
        }
    )

    public_url = supabase.storage.from_(BUCKET_NAME).get_public_url(path_in_bucket)
    return public_url


# ---------- Auth ----------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role_input = request.form["role"].lower()

        try:
            if role_input in ["admin", "superadmin"]:
                # Admin login
                resp = (
                    supabase.table("admins")
                    .select("id, username, password, role, name, email")
                    .eq("username", username)
                    .maybe_single()
                    .execute()
                )
                user = resp.data
                if not user or user["role"].lower() != role_input:
                    return render_template("index.html", error="Invalid credentials or role.")

                if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
                    return render_template("index.html", error="Invalid credentials.")

                session["user"] = {
                    "id": user["id"],
                    "username": user["username"],
                    "role": user["role"].lower(),
                    "name": user.get("name"),
                }
                return redirect(url_for("admin_dashboard"))

            elif role_input == "tenant":
                # Tenant login
                resp = (
                    supabase.table("tenants")
                    .select("id, tenants_username, tenants_password")
                    .eq("tenants_username", username)
                    .maybe_single()
                    .execute()
                )
                user = resp.data
                if not user:
                    return render_template("index.html", error="Invalid tenant credentials.")

                if not bcrypt.checkpw(password.encode("utf-8"), user["tenants_password"].encode("utf-8")):
                    return render_template("index.html", error="Incorrect tenant password.")

                session["user"] = {
                    "id": user["id"],
                    "username": user["tenants_username"],
                    "role": "tenant",
                }
                return redirect(url_for("tenant.tenant_dashboard"))

            else:
                return render_template("index.html", error="Invalid role selected.")

        except Exception as e:
            print("Login error:", e)
            return render_template("index.html", error="Login failed. Try again.")

    return render_template("index.html")

# ---------- Admin ----------
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    admin_id = session['user']['id']
    suggestions = (
        supabase.table('suggestions')
        .select('id')
        .execute()
        .data or []
    )
    marked_rows = supabase.table('admin_read_suggestions').select('suggestion_id').eq('admin_id', admin_id).execute().data or []
    marked = [row['suggestion_id'] for row in marked_rows]
    new_suggestions_count = len([s for s in suggestions if s['id'] not in marked])

    if "user" not in session or session["user"]["role"] not in ["admin", "superadmin"]:
        return redirect("/login")

    user_id = session["user"]["id"]

    # Admin name
    name_response = (
        supabase.table("admins").select("name").eq("id", user_id).single().execute()
    )
    admin_name = name_response.data["name"] if name_response.data else "Admin"

    # Stats
    room_count = (
        supabase.table("rooms").select("id", count="exact").execute().count or 0
    )
    tenant_count = (
        supabase.table("tenants").select("id", count="exact").execute().count or 0
    )
    maintenance_count = (
        supabase.table("maintenance").select("id", count="exact").execute().count or 0
    )

    # Calculate unpaid tenants summary
    transactions = supabase.table('transactions').select('tenant_id, required_amount, submitted_amount').execute().data or []
    unpaid_tenants_count = 0
    total_outstanding_amount = 0
    
    for trans in transactions:
        required = float(trans.get('required_amount', 0))
        submitted = float(trans.get('submitted_amount', 0))
        if submitted < required:
            unpaid_tenants_count += 1
            total_outstanding_amount += (required - submitted)

    return render_template(
        "admin/dashboard.html",
        admin_name=admin_name,
        room_count=room_count,
        tenant_count=tenant_count,
        maintenance_count=maintenance_count,
        new_suggestions_count=new_suggestions_count,
        unpaid_tenants_count=unpaid_tenants_count,
        total_outstanding_amount=total_outstanding_amount
    )


@app.route("/admin/rooms")
@admin_required
def admin_rooms():
    if "user" not in session or session["user"]["role"] not in ["admin", "superadmin"]:
        return redirect("/login")

    rooms_resp = supabase.table("rooms").select("*").execute()
    rooms = rooms_resp.data or []

    tenants_resp = (
        supabase.table("tenants")
        .select("id", "room_id", "tenants_name")
        .execute()
    )
    tenants = tenants_resp.data or []

    room_tenant_map = {t["room_id"]: t for t in tenants}

    for room in rooms:
        tenant = room_tenant_map.get(room["id"])
        room["tenant_name"] = tenant["tenants_name"] if tenant else "N/A"

        # Auto sync status
        if tenant and room["status"] != "occupied":
            supabase.table("rooms").update({"status": "occupied"}).eq("id", room["id"]).execute()
            room["status"] = "occupied"
        elif not tenant and room["status"] == "occupied":
            supabase.table("rooms").update({"status": "available"}).eq("id", room["id"]).execute()
            room["status"] = "available"

    return render_template("admin/rooms.html", rooms=rooms)


@app.route("/admin/tenants")
@admin_required
def admin_tenants():
    if "user" not in session or session["user"]["role"] not in ["admin", "superadmin"]:
        return redirect("/login")

    tenants_resp = supabase.table("tenants").select("*").execute()
    tenants = tenants_resp.data or []
    admin_id = session['user']['id']

    # Append room and emergency contacts
    for tenant in tenants:
        room = None
        if tenant.get("room_id"):
            room = (
                supabase.table("rooms")
                .select("room_number", "floor_number")
                .eq("id", tenant["room_id"])
                .single()
                .execute()
                .data
            )
        tenant["room_number"] = room["room_number"] if room else "-"
        tenant["floor_number"] = room["floor_number"] if room else "-"

        ec_resp = (
            supabase.table("emergency_contacts")
            .select("*")
            .eq("tenant_id", tenant["id"])
            .execute()
        )
        tenant["emergency_contacts"] = ec_resp.data or []

        # Count maintenance requests not attended (pending status and not seen by admin)
        maintenance_pending = (
            supabase.table("maintenance_requests")
            .select("id", count="exact")
            .eq("tenant_id", tenant["id"])
            .eq("status", "pending")
            .eq("admin_seen", False)
            .execute()
        )
        tenant["maintenance_count"] = maintenance_pending.count or 0

        # Count uploads not yet viewed by this admin
        uploads = (
            supabase.table("transaction_proofs")
            .select("id")
            .eq("tenant_id", tenant["id"])
            .execute()
            .data or []
        )
        seen_uploads = (
            supabase.table("tenant_uploads_seen")
            .select("upload_id")
            .eq("admin_id", admin_id)
            .execute()
            .data or []
        )
        seen_ids = [s["upload_id"] for s in seen_uploads]
        tenant["uploads_count"] = len([u for u in uploads if u["id"] not in seen_ids])

        # Count incomplete transactions (not verified)
        unpaid_trans = (
            supabase.table("transactions")
            .select("id", count="exact")
            .eq("tenant_id", tenant["id"])
            .eq("verified", False)
            .execute()
        )
        tenant["unpaid_count"] = unpaid_trans.count or 0

    available_rooms = (
        supabase.table("rooms")
        .select("id", "room_number", "floor_number", "status")
        .eq("status", "available")
        .execute()
        .data
    )

    return render_template(
        "admin/tenants.html",
        tenants=tenants,
        available_rooms=available_rooms,
    )


@app.route("/admin/contracts")
@admin_required
def admin_contracts():
    if "user" not in session or session["user"]["role"] not in ["admin", "superadmin"]:
        return redirect("/login")

    rooms = (
        supabase.table("rooms")
        .select("id, room_number, floor_number")
        .execute()
        .data
        or []
    )
    tenants = (
        supabase.table("tenants").select("room_id", "contract_url").execute().data
        or []
    )

    room_contracts = {
        t["room_id"]: t["contract_url"]
        for t in tenants
        if t.get("contract_url")
    }

    for room in rooms:
        room["contract_url"] = room_contracts.get(room["id"])

    return render_template("admin/contracts.html", rooms=rooms)


@app.route("/admin/contracts/upload", methods=["POST"])
@superadmin_only
def upload_contract():
    if "user" not in session or session["user"]["role"] not in ["admin", "superadmin"]:
        return redirect("/login")

    room_id = request.form.get("room_id")
    file = request.files.get("contract_file")

    if not room_id or not file or not file.filename:
        flash("Room and file are required.", "warning")
        return redirect(url_for("admin_contracts"))

    contract_url = upload_to_supabase_bucket(file)
    if not contract_url:
        flash("Invalid file type or upload failed.", "warning")
        return redirect(url_for("admin_contracts"))

    # Update all tenants linked to this room with the contract URL
    supabase.table("tenants").update({"contract_url": contract_url}).eq("room_id", room_id).execute()

    flash("Contract uploaded / replaced successfully!", "success")
    return redirect(url_for("admin_contracts"))



@app.route("/admin/maintenance", methods=["GET"])
@admin_required
def admin_maintenance():
    admin_id = session['user']['id']
    hidden_rows = supabase.table("admin_hidden_requests").select("request_id").eq("admin_id", admin_id).execute().data or []
    hidden_ids = [row["request_id"] for row in hidden_rows]
    requests = (
        supabase.table('maintenance_requests')
        .select('*')
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    # Filter out hidden requests
    requests = [r for r in requests if r['id'] not in hidden_ids]
    # Fetch tenant usernames for tenant requests
    for r in requests:
        if not r.get("is_admin_only"):
            tenant = supabase.table("tenants").select("tenants_username").eq("id", r["tenant_id"]).maybe_single().execute().data
            r["tenant_username"] = tenant["tenants_username"] if tenant else "Unknown"
    for req in requests:
        req['created_at'] = parse_datetime(req['created_at'])
    return render_template('admin/maintenance.html', requests=requests)

@app.route('/admin/maintenance/resolve', methods=['POST'])
@superadmin_only
@csrf_protect
def admin_maintenance_resolve():
    req_id = request.form.get('id')
    amount_used = request.form.get('amount_used')
    resolved_date = request.form.get('resolved_date')
    supabase.table('maintenance_requests').update({
        'status': 'resolved',
        'amount_used': amount_used,
        'resolved_date': resolved_date
    }).eq('id', req_id).execute()
    flash('Request marked as resolved!', 'success')
    return redirect(url_for('admin_maintenance'))




@app.route('/admin/maintenance/admin_only', methods=['POST'])
@admin_required
@csrf_protect
def admin_maintenance_admin_only():
    admin_id = session['user']['id']
    title = request.form.get('title')
    description = request.form.get('description')
    supabase.table('maintenance_requests').insert({
        'admin_id': admin_id,
        'title': title,
        'description': description,
        'status': 'pending',
        'is_admin_only': True
    }).execute()
    flash('Admin-only maintenance added!', 'success')
    return redirect(url_for('admin_maintenance'))

from flask import render_template, request, redirect, url_for, session, flash
from supabase_client import supabase
from datetime import datetime

def parse_datetime(dt_str):
    try:
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except Exception:
        return dt_str

@app.route('/admin/announcements', methods=['GET', 'POST'])
@admin_required
@csrf_protect
def admin_announcements():
    if request.method == 'POST':
        title = request.form.get('title')
        message = request.form.get('message')
        created_by = session.get('user', {}).get('id')
        if title and message:
            supabase.table('announcements').insert({
                'title': title,
                'message': message,
                'created_by': created_by
            }).execute()
            flash('Announcement posted!', 'success')
        return redirect(url_for('admin_announcements'))
    announcements = (
        supabase.table('announcements')
        .select('*')
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    for ann in announcements:
        ann['created_at'] = parse_datetime(ann['created_at'])
    return render_template('admin/announcements_admin.html', announcements=announcements)

@app.route('/admin/announcements/delete', methods=['POST'])
@superadmin_only
@csrf_protect
def delete_announcement():
    ann_id = request.form.get('id')
    if ann_id:
        supabase.table('announcements').delete().eq('id', ann_id).execute()
        flash('Announcement deleted!', 'success')
    return redirect(url_for('admin_announcements'))


@app.route('/admin/suggestions')
@superadmin_only
def admin_suggestions():
    admin_id = session['user']['id']
    # Fetch hidden suggestions from DB (optional, if you persist this)
    hidden_rows = supabase.table('admin_hidden_suggestions').select('suggestion_id').eq('admin_id', admin_id).execute().data or []
    hidden_ids = [row['suggestion_id'] for row in hidden_rows]
    # Fetch marked as read from DB
    marked_rows = supabase.table('admin_read_suggestions').select('suggestion_id').eq('admin_id', admin_id).execute().data or []
    marked = [row['suggestion_id'] for row in marked_rows]
    suggestions = (
        supabase.table('suggestions')
        .select('*')
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    suggestions = [s for s in suggestions if s['id'] not in hidden_ids]
    for s in suggestions:
        s['created_at'] = parse_datetime(s['created_at'])
    return render_template('admin/suggestions_admin.html', suggestions=suggestions, admin_read_suggestions=marked)

@app.route('/admin/suggestions/mark_read', methods=['POST'])
@admin_required
def mark_suggestion_read_admin():
    sug_id = request.form.get('id')
    admin_id = session['user']['id']
    if sug_id:
        supabase.table('admin_read_suggestions').upsert({
            'admin_id': admin_id,
            'suggestion_id': sug_id
        }).execute()
    return redirect(url_for('admin_suggestions'))

@app.route('/admin/suggestions/delete', methods=['POST'])
@admin_required
def delete_suggestion_admin():
    sug_id = request.form.get('id')
    admin_id = session['user']['id']
    if sug_id:
        # Hide in DB
        supabase.table('admin_hidden_suggestions').upsert({
            'admin_id': admin_id,
            'suggestion_id': sug_id
        }).execute()
        # Mark as read in DB
        supabase.table('admin_read_suggestions').upsert({
            'admin_id': admin_id,
            'suggestion_id': sug_id
        }).execute()
    flash('Suggestion hidden from your view!', 'success')
    return redirect(url_for('admin_suggestions'))

@app.route('/admin/suggestions/clear', methods=['POST'])
@admin_required
def clear_suggestions_admin():
    admin_id = session['user']['id']
    suggestions = (
        supabase.table('suggestions')
        .select('id')
        .execute()
        .data or []
    )
    for s in suggestions:
        # Hide in DB
        supabase.table('admin_hidden_suggestions').upsert({
            'admin_id': admin_id,
            'suggestion_id': s['id']
        }).execute()
        # Mark as read in DB
        supabase.table('admin_read_suggestions').upsert({
            'admin_id': admin_id,
            'suggestion_id': s['id']
        }).execute()
    flash('All suggestions hidden from your view!', 'success')
    return redirect(url_for('admin_suggestions'))


# ---------- Logout ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------- Rooms: Edit ----------
@app.route("/admin/rooms/edit", methods=["POST"])
@admin_required
def edit_room_status():
    if "user" not in session or session["user"]["role"] not in ["admin", "superadmin"]:
        return redirect("/login")

    room_id = request.form["room_id"]
    new_status = request.form["status"]
    new_room_number = request.form["room_number"]
    new_condition = request.form["condition"]

    supabase.table("rooms").update(
        {
            "status": new_status,
            "room_number": new_room_number,
            "condition": new_condition,
        }
    ).eq("id", room_id).execute()

    flash("Room updated!", "success")
    return redirect(url_for("admin_rooms"))


# ---------- Tenants: Add ----------
@app.route("/admin/tenants/add", methods=["POST"])
@admin_required
def add_tenant():
    username = request.form.get('tenants_username')
    # Check in tenants table
    tenant_exists = supabase.table('tenants').select('id').eq('tenants_username', username).execute().data
    # Check in admins table
    admin_exists = supabase.table('admins').select('id').eq('username', username).execute().data

    if tenant_exists or admin_exists:
        flash('Username already exists. Please choose a different one.', 'error')
        return redirect(url_for('admin_rooms'))

    data = request.form
    contract_url = upload_to_supabase_bucket(request.files.get("contract_url"))

    # Hash password
    hashed_password = bcrypt.hashpw(
        data["tenants_password"].encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    tenant_resp = (
        supabase.table("tenants")
        .insert(
            {
                "tenants_name": data["tenants_name"],
                "tenants_phone1": data["tenants_phone1"],
                "tenants_phone2": data.get("tenants_phone2", ""),
                "tenants_email": data["tenants_email"],
                "tenants_username": data["tenants_username"],
                "tenants_password": hashed_password,
                "national_id": data["national_id"],
                "contract_url": contract_url,
                "check_in": data["check_in"],
                "check_out": data["check_out"],
                "room_id": data["room_id"],
                "created_at": datetime.utcnow().isoformat(),
            }
        )
        .execute()
    )
    tenant_id = tenant_resp.data[0]["id"]

    # Set room occupied
    supabase.table("rooms").update({"status": "occupied"}).eq("id", data["room_id"]).execute()

    # Emergency contacts
    supabase.table("emergency_contacts").insert(
        [
            {
                "tenant_id": tenant_id,
                "emergency_contact_name": data["emergency_contact_name1"],
                "emergency_contact_phone": data["emergency_contact_phone1"],
                "relation": data["emergency_relation1"],
            },
            {
                "tenant_id": tenant_id,
                "emergency_contact_name": data["emergency_contact_name2"],
                "emergency_contact_phone": data["emergency_contact_phone2"],
                "relation": data["emergency_relation2"],
            },
        ]
    ).execute()

    flash("Tenant added successfully!", "success")
    return redirect(url_for("admin_rooms"))


# ---------- Tenants: Delete ----------
@app.route("/admin/tenants/delete/<tenant_id>", methods=["POST"])
@superadmin_only
def delete_tenant(tenant_id):
    if "user" not in session or session["user"]["role"] not in ["admin", "superadmin"]:
        return redirect("/login")

    tenant = (
        supabase.table("tenants")
        .select("room_id")
        .eq("id", tenant_id)
        .single()
        .execute()
        .data
    )
    room_id = tenant["room_id"] if tenant else None

    # Get all suggestion IDs for this tenant
    suggestions = supabase.table("suggestions").select("id").eq("tenant_id", tenant_id).execute().data or []
    suggestion_ids = [s["id"] for s in suggestions]

    # Delete from all related tables for each suggestion
    for sug_id in suggestion_ids:
        supabase.table("tenant_hidden_suggestions").delete().eq("suggestion_id", sug_id).execute()
        supabase.table("admin_read_suggestions").delete().eq("suggestion_id", sug_id).execute()
        supabase.table("admin_hidden_suggestions").delete().eq("suggestion_id", sug_id).execute()

    # Now safe to delete suggestions
    supabase.table("suggestions").delete().eq("tenant_id", tenant_id).execute()
    supabase.table("emergency_contacts").delete().eq("tenant_id", tenant_id).execute()
    supabase.table("tenants").delete().eq("id", tenant_id).execute()

    if room_id:
        supabase.table("rooms").update({"status": "available"}).eq("id", room_id).execute()

    flash("Tenant deleted and room set to available.", "success")
    return redirect(url_for("admin_tenants"))


# ---------- Tenants: Edit (upload new contract) ----------
@app.route("/admin/tenants/edit", methods=["POST"])
@admin_required
def edit_tenant():
    tenant_id = request.form.get("tenant_id")
    username = request.form.get("tenants_username")
    national_id = request.form.get("national_id", "")
    # Check for unique username (exclude current tenant)
    tenant_exists = (
        supabase.table('tenants')
        .select('id')
        .eq('tenants_username', username)
        .neq('id', tenant_id)
        .execute()
        .data
    )
    admin_exists = (
        supabase.table('admins')
        .select('id')
        .eq('username', username)
        .execute()
        .data
    )
    if tenant_exists or admin_exists:
        flash('Username already exists. Please choose a different one.', 'error')
        return redirect(url_for('admin_tenants'))

    # Prepare update fields
    update_fields = {
        "tenants_phone1": request.form.get("tenants_phone1"),
        "tenants_phone2": request.form.get("tenants_phone2", ""),
        "tenants_email": request.form.get("tenants_email"),
        "national_id": national_id,
        "check_in": request.form.get("check_in"),
        "check_out": request.form.get("check_out"),
        "room_id": request.form.get("room_id"),
    }

    file = request.files.get("contract_url")
    if file and file.filename:
        contract_url = upload_to_supabase_bucket(file)
        if contract_url:
            update_fields["contract_url"] = contract_url

    # Actually update the tenant
    resp = supabase.table("tenants").update(update_fields).eq("id", tenant_id).execute()

    # --- Emergency Contacts Update ---
    ec1_name = request.form.get("emergency_contact_name1")
    ec1_phone = request.form.get("emergency_contact_phone1")
    ec1_relation = request.form.get("emergency_relation1")
    ec2_name = request.form.get("emergency_contact_name2")
    ec2_phone = request.form.get("emergency_contact_phone2")
    ec2_relation = request.form.get("emergency_relation2")

    # Fetch existing emergency contacts for this tenant
    existing_ecs = (
        supabase.table("emergency_contacts")
        .select("id")
        .eq("tenant_id", tenant_id)
        .execute()
        .data or []
    )

    # Update or insert the first contact
    if len(existing_ecs) > 0:
        supabase.table("emergency_contacts").update({
            "emergency_contact_name": ec1_name,
            "emergency_contact_phone": ec1_phone,
            "relation": ec1_relation
        }).eq("id", existing_ecs[0]["id"]).execute()
    else:
        supabase.table("emergency_contacts").insert({
            "tenant_id": tenant_id,
            "emergency_contact_name": ec1_name,
            "emergency_contact_phone": ec1_phone,
            "relation": ec1_relation
        }).execute()

    # Update or insert the second contact
    if len(existing_ecs) > 1:
        supabase.table("emergency_contacts").update({
            "emergency_contact_name": ec2_name,
            "emergency_contact_phone": ec2_phone,
            "relation": ec2_relation
        }).eq("id", existing_ecs[1]["id"]).execute()
    else:
        supabase.table("emergency_contacts").insert({
            "tenant_id": tenant_id,
            "emergency_contact_name": ec2_name,
            "emergency_contact_phone": ec2_phone,
            "relation": ec2_relation
        }).execute()

    if resp.data:
        flash("Tenant info updated successfully!", "success")
    else:
        flash("No changes made or update failed.", "error")
    return redirect(url_for("admin_tenants"))


# ---------- Tenants: Shift Room ----------
@app.route("/admin/tenants/shift_room", methods=["POST"])
@admin_required
def shift_tenant_room():
    tenant_id = request.form.get("tenant_id")
    new_room_id = request.form.get("room_id")
    if not tenant_id or not new_room_id:
        flash("Missing tenant or room information.", "error")
        return redirect(url_for("admin_tenants"))

    # Optionally fetch room details for updating tenant's floor/room_number
    room = (
        supabase.table("rooms")
        .select("room_number", "floor_number")
        .eq("id", new_room_id)
        .maybe_single()
        .execute()
        .data
    )

    update_fields = {"room_id": new_room_id}
    if room:
        update_fields["room_number"] = room.get("room_number")
        update_fields["floor_number"] = room.get("floor_number")

    resp = (
        supabase.table("tenants")
        .update(update_fields)
        .eq("id", tenant_id)
        .execute()
    )
    if resp.data:
        flash("Tenant shifted to new room successfully!", "success")
    else:
        flash("Failed to shift tenant room.", "error")
    return redirect(url_for("admin_tenants"))


@app.route("/admin/admins")
@superadmin_only
def admin_admins():
    if "user" not in session or session["user"]["role"] != "superadmin":
        return redirect("/login")

    try:
        response = supabase.table("admins").select("*").execute()
        admins = response.data if response.data else []
    except Exception as e:
        print("Error fetching admins:", e)
        admins = []

    return render_template("admin/admins.html", admins=admins)

@app.route("/admin/admins/create", methods=["POST"])
@superadmin_only
def create_admin():
    if "user" not in session or session["user"]["role"] != "superadmin":
        return redirect("/login")

    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")

    if not all([name, username, email, password]):
        flash("All fields are required.", "error")
        return redirect(url_for("admin_admins"))

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        supabase.table("admins").insert({
            "name": name,
            "username": username,
            "email": email,
            "password": hashed_password,
            "role": "admin"
        }).execute()
        flash(f"Admin '{username}' created successfully!", "success")
    except Exception as e:
        print("Error creating admin:", e)
        flash("Failed to create admin. Username or email may already exist.", "error")

    return redirect(url_for("admin_admins"))


@app.route("/admin/admins/reset_password", methods=["POST"])
@superadmin_only
def reset_admin_password():
    if "user" not in session or session["user"]["role"] != "superadmin":
        return redirect("/login")

    admin_id = request.form.get("admin_id")
    new_password = request.form.get("new_password")

    if not admin_id or not new_password:
        flash("Admin ID and new password are required.", "error")
        return redirect(url_for("admin_admins"))

    hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        supabase.table("admins").update({"password": hashed_password}).eq("id", admin_id).execute()
        flash("Password reset successfully!", "success")
    except Exception as e:
        print("Error resetting password:", e)
        flash("Failed to reset password.", "error")

    return redirect(url_for("admin_admins"))


@app.route("/admin/admins/delete", methods=["POST"])
@superadmin_only
def delete_admin():
    if "user" not in session or session["user"]["role"] != "superadmin":
        return redirect("/login")

    admin_id = request.form.get("admin_id")
    if not admin_id:
        flash("Invalid admin ID.", "error")
        return redirect(url_for("admin_admins"))

    try:
        supabase.table("admins").delete().eq("id", admin_id).execute()
        flash("Admin deleted successfully.", "success")
    except Exception as e:
        print("Error deleting admin:", e)
        flash("Failed to delete admin.", "error")

    return redirect(url_for("admin_admins"))

@app.route("/admin/admins/reset_own_password", methods=["POST"])
def reset_own_password():
    if "user" not in session or session["user"]["role"] not in ["admin", "superadmin"]:
        return redirect("/login")

    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")

    if not current_password or not new_password:
        flash("Both current and new passwords are required.", "error")
        return redirect(url_for("admin_admins"))

    try:
        user = supabase.table("admins").select("*").eq("id", session["user"]["id"]).single().execute().data
        if user and bcrypt.checkpw(current_password.encode("utf-8"), user["password"].encode("utf-8")):
            hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            supabase.table("admins").update({"password": hashed_password}).eq("id", user["id"]).execute()
            flash("Your password has been updated!", "success")
        else:
            flash("Current password is incorrect.", "error")
    except Exception as e:
        print("Error resetting own password:", e)
        flash("Failed to reset password.", "error")

    return redirect(url_for("admin_admins"))




# ---------- Tenant ----------


def parse_datetime(dt_str):
    try:
        # Handles both with and without timezone
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except Exception:
        return dt_str

@app.route('/admin/transactions', methods=['GET'])
@admin_required
def admin_transactions():
    # Get filter parameters
    tenant_filter_id = request.args.get('tenant_id')
    transaction_id = request.args.get('transaction_id')
    floor_filter = request.args.get('floor')
    ownership_filter = request.args.get('ownership')
    contract_month = request.args.get('contract_month')
    contract_year = request.args.get('contract_year')
    search_query = request.args.get('search')

    # Build base query
    query = supabase.table('transactions').select('*').order('created_at', desc=True)
    
    # Apply filters
    if tenant_filter_id:
        query = query.eq('tenant_id', tenant_filter_id)
    if transaction_id:
        query = query.eq('id', transaction_id)
    if floor_filter:
        query = query.eq('floor_number', floor_filter)
    
    transactions = query.execute().data or []

    # Get all tenants with room information
    tenants_resp = supabase.table('tenants').select('id, tenants_name, room_id, check_out').order('tenants_name').execute()
    tenants = tenants_resp.data or []

    # Get room information for tenants
    room_ids = [t.get('room_id') for t in tenants if t.get('room_id')]
    rooms_by_id = {}
    if room_ids:
        try:
            rooms_resp = (
                supabase.table('rooms')
                .select('id, room_number, floor_number')
                .in_('id', room_ids)
                .execute()
            )
            for r in (rooms_resp.data or []):
                rooms_by_id[r['id']] = r
        except Exception:
            rooms_by_id = {}

    # Enrich tenants with room information
    for t in tenants:
        r = rooms_by_id.get(t.get('room_id'))
        if r:
            t['room_number'] = r.get('room_number')
            t['floor_number'] = r.get('floor_number')

    # Apply additional filters
    if ownership_filter == 'owned':
        # Filter tenants who have completed payments
        owned_tenant_ids = []
        for trans in transactions:
            if trans.get('required_amount') and trans.get('submitted_amount'):
                if float(trans.get('submitted_amount', 0)) >= float(trans.get('required_amount', 0)):
                    owned_tenant_ids.append(trans.get('tenant_id'))
        transactions = [t for t in transactions if t.get('tenant_id') in owned_tenant_ids]
    
    elif ownership_filter == 'not_owned':
        # Filter tenants who haven't completed payments
        not_owned_tenant_ids = []
        for trans in transactions:
            if trans.get('required_amount') and trans.get('submitted_amount'):
                if float(trans.get('submitted_amount', 0)) < float(trans.get('required_amount', 0)):
                    not_owned_tenant_ids.append(trans.get('tenant_id'))
        transactions = [t for t in transactions if t.get('tenant_id') in not_owned_tenant_ids]

    # Filter by contract expiry month/year
    if contract_month and contract_year:
        filtered_transactions = []
        for trans in transactions:
            tenant_id = trans.get('tenant_id')
            tenant = next((t for t in tenants if t.get('id') == tenant_id), None)
            if tenant and tenant.get('check_out'):
                try:
                    check_out_date = datetime.fromisoformat(tenant.get('check_out').replace('Z', '+00:00'))
                    if check_out_date.month == int(contract_month) and check_out_date.year == int(contract_year):
                        filtered_transactions.append(trans)
                except:
                    pass
        transactions = filtered_transactions

    # Search functionality
    if search_query:
        search_lower = search_query.lower()
        filtered_transactions = []
        for trans in transactions:
            tenant_id = trans.get('tenant_id')
            tenant = next((t for t in tenants if t.get('id') == tenant_id), None)
            if tenant and (
                search_lower in tenant.get('tenants_name', '').lower() or
                search_lower in trans.get('room_number', '').lower() or
                search_lower in trans.get('floor_number', '').lower()
            ):
                filtered_transactions.append(trans)
        transactions = filtered_transactions

    # Calculate payment status for each transaction
    for trans in transactions:
        required = float(trans.get('required_amount', 0))
        submitted = float(trans.get('submitted_amount', 0))
        remaining = max(0, required - submitted)
        
        trans['payment_status'] = 'paid' if submitted >= required else 'partial'
        trans['remaining_amount'] = remaining
        trans['is_fully_paid'] = submitted >= required

    return render_template('admin/transactions.html', 
                          transactions=transactions, 
                          tenants=tenants,
                          floor_filter=floor_filter,
                          ownership_filter=ownership_filter,
                          contract_month=contract_month,
                          contract_year=contract_year,
                          search_query=search_query)

@app.route('/admin/transactions/add', methods=['POST'])
@superadmin_only
def add_transaction():
    floor_number = request.form.get('floor_number')
    room_number = request.form.get('room_number')
    tenant_id = request.form.get('tenant_id')
    required_amount = request.form.get('required_amount')
    submitted_amount = request.form.get('submitted_amount')
    transaction_date = request.form.get('transaction_date')
    check_in = request.form.get('check_in')
    check_out = request.form.get('check_out')

    # Normalize floor naming and types
    if floor_number is not None:
        fn = str(floor_number).strip().lower()
        if fn in ['0', 'ground', 'g']:
            floor_number = 'ground'

    # Coerce numeric inputs safely
    def to_float(val):
        try:
            return float(val) if val not in (None, '') else None
        except Exception:
            return None

    required_amount_val = to_float(required_amount)
    submitted_amount_val = to_float(submitted_amount)

    # Preserve tenant_id as-is (supports UUIDs). Use None if empty
    tenant_id_val = tenant_id if tenant_id not in (None, '') else None

    tenant_name = None
    if tenant_id:
        tenant_resp = (
            supabase.table('tenants')
            .select('tenants_name')
            .eq('id', tenant_id)
            .maybe_single()
            .execute()
        )
        tenant_name = tenant_resp.data['tenants_name'] if tenant_resp.data else None

    supabase.table('transactions').insert({
        'tenant_id': tenant_id_val,
        'floor_number': floor_number,
        'room_number': room_number,
        'tenant_name': tenant_name,
        'required_amount': required_amount_val,
        'submitted_amount': submitted_amount_val,
        'transaction_date': transaction_date,
        'check_in': check_in,
        'check_out': check_out,
        'verified': True,  # Admin-added transactions are auto-verified
        'verified_by': session['user']['id'],  # Track who verified it
        'registered_by': session['user']['id']  # Track who registered it
    }).execute()

    # Update tenant's next_due_date to the check_out date (furthest due date)
    if tenant_id_val and check_out:
        try:
            # Get current tenant's next_due_date
            tenant_data = supabase.table('tenants').select('next_due_date').eq('id', tenant_id_val).maybe_single().execute().data
            if tenant_data:
                current_due = tenant_data.get('next_due_date')
                # Update if new check_out is later than current due date or if no due date exists
                if not current_due or check_out > current_due:
                    supabase.table('tenants').update({'next_due_date': check_out}).eq('id', tenant_id_val).execute()
        except Exception as e:
            print(f'Error updating next_due_date: {e}')

    flash('Transaction added!', 'success')
    return redirect(url_for('admin_transactions'))

@app.route('/admin/transactions/edit', methods=['POST'])
@superadmin_only
@csrf_protect
def edit_transaction():
    trans_id = request.form.get('id')
    required_amount = request.form.get('required_amount')
    submitted_amount = request.form.get('submitted_amount')
    transaction_date = request.form.get('transaction_date')
    check_in = request.form.get('check_in')
    check_out = request.form.get('check_out')

    # Coerce numeric inputs safely
    def to_float(val):
        try:
            return float(val) if val not in (None, '') else None
        except Exception:
            return None

    required_amount_val = to_float(required_amount)
    submitted_amount_val = to_float(submitted_amount)

    # Get the transaction to find tenant_id
    trans_data = supabase.table('transactions').select('tenant_id').eq('id', trans_id).maybe_single().execute().data

    supabase.table('transactions').update({
        'required_amount': required_amount_val,
        'submitted_amount': submitted_amount_val,
        'transaction_date': transaction_date,
        'check_in': check_in,
        'check_out': check_out
    }).eq('id', trans_id).execute()

    # Update tenant's next_due_date if check_out changed
    if trans_data and trans_data.get('tenant_id') and check_out:
        try:
            tenant_id = trans_data['tenant_id']
            # Get all transactions for this tenant to find the furthest check_out date
            all_trans = supabase.table('transactions').select('check_out').eq('tenant_id', tenant_id).execute().data or []
            furthest_date = max([t.get('check_out') for t in all_trans if t.get('check_out')], default=None)
            if furthest_date:
                supabase.table('tenants').update({'next_due_date': furthest_date}).eq('id', tenant_id).execute()
        except Exception as e:
            print(f'Error updating next_due_date: {e}')

    flash('Transaction updated!', 'success')
    return redirect(url_for('admin_transactions'))

@app.route('/admin/proofs', methods=['GET'])
@admin_required
def admin_proofs():
    proofs = (
        supabase.table('transaction_proofs')
        .select('*')
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    return render_template('admin/proofs.html', proofs=proofs)

@app.route('/admin/proofs/approve', methods=['POST'])
@admin_required
def admin_proofs_approve():
    proof_id = request.form.get('id')
    if proof_id:
        supabase.table('transaction_proofs').update({'status': 'approved'}).eq('id', proof_id).execute()
        flash('Proof approved!', 'success')
    return redirect(url_for('admin_proofs'))

@app.route('/admin/proofs/reject', methods=['POST'])
@admin_required
def admin_proofs_reject():
    proof_id = request.form.get('id')
    if proof_id:
        supabase.table('transaction_proofs').update({'status': 'rejected'}).eq('id', proof_id).execute()
        flash('Proof rejected!', 'success')
    return redirect(url_for('admin_proofs'))

@app.route('/admin/finance')
@superadmin_only
def admin_finance():
    # Get date range filter if provided
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    # Fetch all verified transactions (Debit entries - income)
    transactions_query = supabase.table('transactions').select('*, registered_by').eq('verified', True).order('transaction_date', desc=True)
    transactions = transactions_query.execute().data or []

    # Fetch all expenses (Credit entries)
    expenses_query = supabase.table('expenses').select('*, registered_by').order('expense_date', desc=True)
    expenses = expenses_query.execute().data or []

    # Get admin names for registered_by
    admin_ids = set()
    for t in transactions:
        if t.get('registered_by'):
            admin_ids.add(t['registered_by'])
    for e in expenses:
        if e.get('registered_by'):
            admin_ids.add(e['registered_by'])

    admin_names = {}
    if admin_ids:
        admins = supabase.table('admins').select('id, name').in_('id', list(admin_ids)).execute().data or []
        admin_names = {a['id']: a.get('name', 'Unknown') for a in admins}

    # Build ledger entries
    ledger_entries = []

    # Add transactions as Debit
    for t in transactions:
        trans_date = t.get('transaction_date') or t.get('created_at', '')[:10]
        ledger_entries.append({
            'date': trans_date,
            'type': 'Debit',
            'amount': float(t.get('submitted_amount') or 0),
            'description': f"Payment from {t.get('tenant_name', 'Unknown')} - Room {t.get('room_number', 'N/A')}",
            'registered_by': admin_names.get(t.get('registered_by'), 'Unknown'),
            'created_at': t.get('created_at', '')
        })

    # Add expenses as Credit
    for e in expenses:
        ledger_entries.append({
            'date': e.get('expense_date', '')[:10] if e.get('expense_date') else '',
            'type': 'Credit',
            'amount': float(e.get('amount') or 0),
            'description': e.get('reason', 'No description'),
            'registered_by': admin_names.get(e.get('registered_by'), 'Unknown'),
            'created_at': e.get('created_at', '')
        })

    # Sort ledger by date descending
    ledger_entries.sort(key=lambda x: x.get('date', ''), reverse=True)

    # Apply date filter if provided
    filtered_entries = ledger_entries
    if date_from and date_to:
        filtered_entries = [e for e in ledger_entries if date_from <= e.get('date', '') <= date_to]

    # Calculate totals for filtered entries
    total_debit = sum(e['amount'] for e in filtered_entries if e['type'] == 'Debit')
    total_credit = sum(e['amount'] for e in filtered_entries if e['type'] == 'Credit')
    balance = total_debit - total_credit

    # Calculate overall totals (no filter)
    overall_debit = sum(e['amount'] for e in ledger_entries if e['type'] == 'Debit')
    overall_credit = sum(e['amount'] for e in ledger_entries if e['type'] == 'Credit')
    overall_balance = overall_debit - overall_credit

    return render_template('admin/finance.html',
                         ledger_entries=filtered_entries,
                         total_debit=total_debit,
                         total_credit=total_credit,
                         balance=balance,
                         overall_debit=overall_debit,
                         overall_credit=overall_credit,
                         overall_balance=overall_balance,
                         date_from=date_from,
                         date_to=date_to)


@app.route('/admin/finance/add_expense', methods=['POST'])
@superadmin_only
@csrf_protect
def add_expense():
    amount = request.form.get('amount')
    reason = request.form.get('reason')
    expense_date = request.form.get('expense_date')

    if not amount or not reason:
        flash('Amount and reason are required!', 'error')
        return redirect(url_for('admin_finance'))

    try:
        amount_val = float(amount)
        supabase.table('expenses').insert({
            'amount': amount_val,
            'reason': reason,
            'expense_date': expense_date or datetime.now().date().isoformat(),
            'registered_by': session['user']['id']
        }).execute()
        flash('Expense added successfully!', 'success')
    except Exception as e:
        print(f'Error adding expense: {e}')
        flash('Failed to add expense!', 'error')

    return redirect(url_for('admin_finance'))


# ---------- Per-tenant Admin Views ----------
@app.route('/admin/tenants/<tenant_id>/maintenance')
@admin_required
def admin_tenant_maintenance(tenant_id):
    # Show only this tenant's maintenance requests
    requests = (
        supabase.table('maintenance_requests')
        .select('*')
        .eq('tenant_id', tenant_id)
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    for r in requests:
        r['created_at'] = parse_datetime(r.get('created_at', ''))
    tenant = (
        supabase.table('tenants')
        .select('id, tenants_name, tenants_username')
        .eq('id', tenant_id)
        .maybe_single()
        .execute()
        .data
    )
    return render_template('admin/tenant_maintenance.html', tenant=tenant, requests=requests)


@app.route('/admin/tenants/<tenant_id>/transactions')
@admin_required
def admin_tenant_transactions(tenant_id):
    # Show only this tenant's transactions
    transactions = (
        supabase.table('transactions')
        .select('*')
        .eq('tenant_id', tenant_id)
        .order('created_at', desc=True)
        .execute()
        .data or []
    )

    # Calculate payment meta like in admin_transactions
    for t in transactions:
        required = float(t.get('required_amount', 0) or 0)
        submitted = float(t.get('submitted_amount', 0) or 0)
        t['payment_status'] = 'paid' if submitted >= required else 'partial'
        t['remaining_amount'] = max(0, required - submitted)

    tenant = (
        supabase.table('tenants')
        .select('id, tenants_name, tenants_username, room_id')
        .eq('id', tenant_id)
        .maybe_single()
        .execute()
        .data
    )
    return render_template('admin/tenant_transactions.html', tenant=tenant, transactions=transactions)


@app.route('/admin/tenants/<tenant_id>/uploads')
@admin_required
def admin_tenant_uploads(tenant_id):
    admin_id = session['user']['id']
    # Show only this tenant's proofs/uploads
    proofs = (
        supabase.table('transaction_proofs')
        .select('*')
        .eq('tenant_id', tenant_id)
        .order('created_at', desc=True)
        .execute()
        .data or []
    )

    # Check which uploads have been seen by this admin
    seen_uploads = (
        supabase.table("tenant_uploads_seen")
        .select("upload_id")
        .eq("admin_id", admin_id)
        .execute()
        .data or []
    )
    seen_ids = [s["upload_id"] for s in seen_uploads]

    # Add seen status to each proof
    for proof in proofs:
        proof["seen_by_admin"] = proof["id"] in seen_ids

    tenant = (
        supabase.table('tenants')
        .select('id, tenants_name, tenants_username')
        .eq('id', tenant_id)
        .maybe_single()
        .execute()
        .data
    )
    return render_template('admin/tenant_uploads.html', tenant=tenant, proofs=proofs, tenant_id=tenant_id)


@app.route('/admin/tenants/<tenant_id>/maintenance/seen', methods=['POST'])
@admin_required
@csrf_protect
def admin_tenant_maintenance_seen(tenant_id):
    req_id = request.form.get('id')
    if req_id:
        try:
            supabase.table('maintenance_requests').update({
                'admin_seen': True
            }).eq('id', req_id).eq('tenant_id', tenant_id).execute()
            flash('Marked as seen.', 'success')
        except Exception as e:
            print('Mark seen error:', e)
            flash('Failed to mark as seen.', 'error')
    return redirect(url_for('admin_tenant_maintenance', tenant_id=tenant_id))


@app.route('/admin/tenants/<tenant_id>/maintenance/reply', methods=['POST'])
@admin_required
@csrf_protect
def admin_tenant_maintenance_reply(tenant_id):
    req_id = request.form.get('id')
    reply = request.form.get('reply')
    if req_id and reply:
        try:
            supabase.table('maintenance_requests').update({
                'admin_reply': reply,
                'updated_at': datetime.utcnow().isoformat()
            }).eq('id', req_id).eq('tenant_id', tenant_id).execute()
            flash('Reply sent to tenant!', 'success')
        except Exception as e:
            print('Reply error:', e)
            flash('Failed to send reply.', 'error')
    return redirect(url_for('admin_tenant_maintenance', tenant_id=tenant_id))


@app.route('/admin/tenants/<tenant_id>/uploads/mark_seen', methods=['POST'])
@admin_required
@csrf_protect
def admin_tenant_upload_mark_seen(tenant_id):
    admin_id = session['user']['id']
    upload_id = request.form.get('upload_id')
    if upload_id:
        try:
            # Use upsert to avoid duplicates
            supabase.table('tenant_uploads_seen').upsert({
                'admin_id': admin_id,
                'upload_id': upload_id
            }).execute()
            flash('Upload marked as seen!', 'success')
        except Exception as e:
            print('Mark upload seen error:', e)
            flash('Failed to mark upload as seen.', 'error')
    return redirect(url_for('admin_tenant_uploads', tenant_id=tenant_id))


@app.route('/admin/uploads', methods=['GET'])
@admin_required
def admin_uploads():
    proofs = (
        supabase.table('transaction_proofs')
        .select('*')
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    return render_template('admin/proofs.html', proofs=proofs)

@app.route("/admin/maintenance/hide/<req_id>", methods=["POST"])
@superadmin_only
def admin_hide_maintenance(req_id):
    admin_id = session['user']['id']
    supabase.table("admin_hidden_requests").upsert({
        "admin_id": admin_id,
        "request_id": req_id
    }).execute()
    flash("Request hidden from your dashboard.", "success")
    return redirect(url_for("admin_maintenance"))

if __name__ == "__main__":
    app.run(debug=True)
