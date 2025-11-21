from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from supabase_client import supabase
from datetime import datetime
from functools import wraps

tenant_bp = Blueprint('tenant', __name__, url_prefix="/tenant")

def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == 'POST':
            form_token = request.form.get('csrf_token')
            if not form_token or form_token != session.get('csrf_token'):
                flash('Invalid or missing CSRF token.', 'error')
                return redirect(request.referrer or url_for('tenant.tenant_dashboard'))
        return view(*args, **kwargs)
    return wrapped

def parse_datetime(dt_str):
    try:
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except Exception:
        return dt_str

@tenant_bp.route("/dashboard")
def tenant_dashboard():
    if "user" not in session or session["user"]["role"] != "tenant":
        return redirect("/")
    tenant_id = session['user']['id']
    announcements = (
        supabase.table('announcements')
        .select('id')
        .execute()
        .data or []
    )
    read_rows = supabase.table('tenant_read_announcements').select('announcement_id').eq('tenant_id', tenant_id).execute().data or []
    marked = [row['announcement_id'] for row in read_rows]
    new_announcements_count = len([a for a in announcements if a['id'] not in marked])
    tenant_name = session["user"].get("name", session["user"]["username"])
    
    # Get tenant's transaction and payment status
    try:
        transaction_resp = supabase.table('transactions').select('*').eq('tenant_id', tenant_id).order('created_at', desc=True).execute()
        transactions = transaction_resp.data or []
        transaction = transactions[0] if transactions else None
    except Exception:
        transaction = None
    
    try:
        tenant_info = supabase.table('tenants').select('check_out, next_due_date').eq('id', tenant_id).single().execute().data
    except Exception:
        tenant_info = None

    payment_status = None
    remaining_amount = 0
    due_date = None
    farthest_due_date = None

    if transaction:
        required = float(transaction.get('required_amount', 0))
        submitted = float(transaction.get('submitted_amount', 0))
        remaining_amount = max(0, required - submitted)
        payment_status = 'paid' if submitted >= required else 'partial'

    # Use next_due_date from tenants table (updated automatically when transactions are added)
    if tenant_info:
        if tenant_info.get('next_due_date'):
            farthest_due_date = tenant_info.get('next_due_date')
            due_date = farthest_due_date
        elif tenant_info.get('check_out'):
            # Fallback to check_out if next_due_date not set
            due_date = tenant_info.get('check_out')
            farthest_due_date = due_date
    
    # Pull most recent admin reply to maintenance if stored
    latest_reply = None
    try:
        replies_resp = (
            supabase.table('maintenance_requests')
            .select('admin_reply')
            .eq('tenant_id', tenant_id)
            .order('updated_at', desc=True)
            .limit(1)
            .execute()
        )
        rows = replies_resp.data or []
        if rows and rows[0].get('admin_reply'):
            latest_reply = rows[0]['admin_reply']
    except Exception:
        latest_reply = None

    return render_template("tenant/dashboard.html", 
                         tenant_name=tenant_name, 
                         new_announcements_count=new_announcements_count,
                         payment_status=payment_status,
                         remaining_amount=remaining_amount,
                         due_date=due_date,
                         farthest_due_date=farthest_due_date,
                         latest_maintenance_reply=latest_reply)

@tenant_bp.route('/profile')
def profile():
    tenant_id = session.get('user', {}).get('id')
    tenant = supabase.table('tenants').select('*').eq('id', tenant_id).single().execute().data
    room = None
    if tenant and tenant.get("room_id"):
        room = (
            supabase.table("rooms")
            .select("room_number", "floor_number")
            .eq("id", tenant["room_id"])
            .single()
            .execute()
            .data
        )
    emergency_contacts = (
        supabase.table('emergency_contacts')
        .select('*')
        .eq('tenant_id', tenant_id)
        .execute()
        .data or []
    )
    return render_template(
        'tenant/ten_profile.html',
        tenant=tenant,
        room=room,
        emergency_contacts=emergency_contacts
    )

@tenant_bp.route('/profile/update', methods=['POST'])
@csrf_protect
def update_profile():
    tenant_id = session.get('user', {}).get('id')
    phone = request.form.get('phone')
    supabase.table('tenants').update({'tenants_phone1': phone}).eq('id', tenant_id).execute()

    # Update each emergency contact
    contact_ids = request.form.getlist('contact_id')
    names = request.form.getlist('emergency_name')
    phones = request.form.getlist('emergency_phone')
    relations = request.form.getlist('relation')

    for i, cid in enumerate(contact_ids):
        supabase.table('emergency_contacts').update({
            'emergency_contact_name': names[i],
            'emergency_contact_phone': phones[i],
            'relation': relations[i]
        }).eq('id', cid).execute()

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('tenant.profile'))

@tenant_bp.route('/profile/upload', methods=['POST'])
@csrf_protect
def upload_profile_picture():
    tenant_id = session.get('user', {}).get('id')
    file = request.files.get('profile_picture')
    if file and file.filename:
        file_path = f"profile_pictures/{tenant_id}_{file.filename}"
        file_bytes = file.read()
        supabase.storage.from_('profile-pictures').upload(file_path, file_bytes, {"content-type": file.mimetype, "upsert": "true"})
        profile_url = supabase.storage.from_('profile-pictures').get_public_url(file_path)
        supabase.table('tenants').update({'profile_picture': profile_url}).eq('id', tenant_id).execute()
        flash('Profile picture updated!', 'success')
    else:
        flash('No file selected.', 'error')
    return redirect(url_for('tenant.profile'))

@tenant_bp.route('/announcements')
def tenant_announcements():
    tenant_id = session['user']['id']
    announcements = (
        supabase.table('announcements')
        .select('*')
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    for ann in announcements:
        ann['created_at'] = parse_datetime(ann['created_at'])
    # Fetch marked as read from DB
    read_rows = supabase.table('tenant_read_announcements').select('announcement_id').eq('tenant_id', tenant_id).execute().data or []
    marked = [row['announcement_id'] for row in read_rows]
    return render_template('tenant/announcements.html', announcements=announcements, tenant_read_announcements=marked)

@tenant_bp.route('/announcements/mark_read', methods=['POST'])
def mark_announcement_read_tenant():
    ann_id = request.form.get('id')
    tenant_id = session['user']['id']
    if ann_id:
        # Insert if not already marked
        supabase.table('tenant_read_announcements').upsert({
            'tenant_id': tenant_id,
            'announcement_id': ann_id
        }).execute()
    return redirect(url_for('tenant.tenant_announcements'))

@tenant_bp.route('/suggestions', methods=['GET', 'POST'])
@csrf_protect
def tenant_suggestions():
    tenant_id = session.get('user', {}).get('id')
    if request.method == 'POST':
        tenant_name = session.get('user', {}).get('name', 'Unknown')
        message = request.form.get('message')
        if message:
            supabase.table('suggestions').insert({
                'tenant_id': tenant_id,
                'tenant_name': tenant_name,
                'message': message
            }).execute()
            flash('Suggestion submitted!', 'success')
        return redirect(url_for('tenant.tenant_suggestions'))

    # Get hidden suggestion IDs from DB
    hidden_rows = supabase.table('tenant_hidden_suggestions').select('suggestion_id').eq('tenant_id', tenant_id).execute().data or []
    hidden_ids = [row['suggestion_id'] for row in hidden_rows]

    suggestions = (
        supabase.table('suggestions')
        .select('*')
        .eq('tenant_id', tenant_id)
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    suggestions = [s for s in suggestions if s['id'] not in hidden_ids]
    for s in suggestions:
        s['created_at'] = parse_datetime(s['created_at'])
    return render_template('tenant/suggestions.html', suggestions=suggestions)

@tenant_bp.route('/suggestions/delete', methods=['POST'])
def delete_suggestion_tenant():
    sug_id = request.form.get('id')
    tenant_id = session['user']['id']
    if sug_id:
        supabase.table('tenant_hidden_suggestions').upsert({
            'tenant_id': tenant_id,
            'suggestion_id': sug_id
        }).execute()
    flash('Suggestion hidden from your view!', 'success')
    return redirect(url_for('tenant.tenant_suggestions'))

@tenant_bp.route('/suggestions/clear', methods=['POST'])
def clear_suggestions_tenant():
    tenant_id = session['user']['id']
    suggestions = (
        supabase.table('suggestions')
        .select('id')
        .eq('tenant_id', tenant_id)
        .execute()
        .data or []
    )
    for s in suggestions:
        supabase.table('tenant_hidden_suggestions').upsert({
            'tenant_id': tenant_id,
            'suggestion_id': s['id']
        }).execute()
    flash('All your suggestions hidden from your view!', 'success')
    return redirect(url_for('tenant.tenant_suggestions'))

@tenant_bp.route("/maintenance", methods=["GET", "POST"])
@csrf_protect
def tenant_maintenance():
    if request.method == "POST":
        tenant_id = session['user']['id']
        title = request.form.get('title')
        description = request.form.get('description')
        supabase.table('maintenance_requests').insert({
            'tenant_id': tenant_id,
            'title': title,
            'description': description,
            'status': 'pending',
            'is_admin_only': False
        }).execute()
        flash('Maintenance request submitted!', 'success')
        return redirect(url_for('tenant.tenant_maintenance'))

    tenant_id = session['user']['id']
    hidden_rows = supabase.table("tenant_hidden_requests").select("request_id").eq("tenant_id", tenant_id).execute().data or []
    hidden_ids = [row["request_id"] for row in hidden_rows]
    requests = supabase.table('maintenance_requests').select('*').eq('tenant_id', session['user']['id']).order('created_at', desc=True).execute().data or []
    requests = [r for r in requests if r['id'] not in hidden_ids]
    for req in requests:
        req['created_at'] = parse_datetime(req['created_at'])
    return render_template('tenant/maintenance.html', requests=requests)

# In tenant_routes.py (for tenant)


@tenant_bp.route("/maintenance/hide/<req_id>", methods=["POST"])
def tenant_hide_maintenance(req_id):
    tenant_id = session['user']['id']
    supabase.table("tenant_hidden_requests").upsert({
        "tenant_id": tenant_id,
        "request_id": req_id
    }).execute()
    flash("Request hidden from your dashboard.", "success")
    return redirect(url_for("tenant.tenant_maintenance"))

@tenant_bp.route('/transactions')
def tenant_transactions():
    tenant_id = session['user']['id']
    transactions = (
        supabase.table('transactions')
        .select('*')
        .eq('tenant_id', tenant_id)
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    return render_template('tenant/transactions.html', transactions=transactions)

@tenant_bp.route('/proofs', methods=['GET'])
def tenant_proofs():
    tenant_id = session['user']['id']
    proofs = (
        supabase.table('transaction_proofs')
        .select('*')
        .eq('tenant_id', tenant_id)
        .order('created_at', desc=True)
        .execute()
        .data or []
    )
    return render_template('tenant/proofs.html', proofs=proofs)

@tenant_bp.route('/proofs/upload', methods=['POST'])
@csrf_protect
def tenant_proofs_upload():
    tenant_id = session['user']['id']
    amount = request.form.get('amount')
    message = request.form.get('message')
    file = request.files.get('proof_file')
    if file and file.filename:
        file_path = f"proof_uploads/{tenant_id}_{file.filename}"
        file_bytes = file.read()
        supabase.storage.from_('proof-uploads').upload(file_path, file_bytes, {"content-type": file.mimetype, "upsert": "true"})
        file_url = supabase.storage.from_('proof-uploads').get_public_url(file_path)
        supabase.table('transaction_proofs').insert({
            'tenant_id': tenant_id,
            'amount': amount,
            'file_url': file_url,
            'message': message,
            'status': 'pending'
        }).execute()
        flash('Proof uploaded successfully!', 'success')
    else:
        flash('No file selected.', 'error')
    return redirect(url_for('tenant.tenant_proofs'))