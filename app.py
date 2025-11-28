from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, flash
from config import Config
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
import smtplib
from email.mime.text import MIMEText
import secrets
import random
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import io
import os
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import json
from pymongo import ReturnDocument
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph

app = Flask(__name__)
app.config.from_object(Config)

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Safe idempotency index creation
try:
    # Remove explicit null idempotency_key (these break unique indexes)
    mongo.db.transactions.update_many(
        {"idempotency_key": None},
        {"$unset": {"idempotency_key": ""}}
    )

    # Unique index only when idempotency_key exists and is not null
    mongo.db.transactions.create_index(
        [("user_id", 1), ("idempotency_key", 1)],
        unique=True,
        name="user_id_idempotency_key_unique",
        partialFilterExpression={"idempotency_key": {"$exists": True, "$ne": None}}
    )
except Exception:
    app.logger.exception("Could not create idempotency index on transactions (non-fatal)")


# Email helper (OTP / reset)
def send_email(to_email: str, subject: str, body: str):
    """Send email via SMTP configured in app.config or print link/OTP to stdout for dev."""
    smtp_server = app.config.get("SMTP_SERVER")
    smtp_port = int(app.config.get("SMTP_PORT", 587) or 587)
    smtp_user = app.config.get("SMTP_USERNAME")
    smtp_pass = app.config.get("SMTP_PASSWORD")
    from_addr = app.config.get("MAIL_FROM") or smtp_user or "no-reply@example.com"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email or ""

    if not smtp_server or not smtp_user:
        # fallback for dev — print OTP or link
        app.logger.info("SMTP not configured; printing email to console")
        print("=== EMAIL OUT ===")
        print("To:", to_email)
        print("Subject:", subject)
        print(body)
        print("=================")
        return

    try:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(from_addr, [to_email], msg.as_string())
    except Exception:
        app.logger.exception("Failed to send email")
    finally:
        try:
            server.quit()
        except Exception:
            pass

# Notification helper (Mongo)
def create_notification(message: str, ntype: str = "info", data: dict = None, is_read: bool = False):
    """
    Inserts a notification doc into mongo.db.notifications
    Document:
      { message, type, data, created_at, is_read }
    """
    doc = {
        "message": message,
        "type": ntype,
        "data": data or {},
        "created_at": datetime.utcnow(),
        "is_read": bool(is_read)
    }
    try:
        mongo.db.notifications.insert_one(doc)
    except Exception:
        app.logger.exception("Failed to create notification")

def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        return mongo.db.users.find_one({"_id": ObjectId(uid)})
    except Exception:
        return None

# Authentication & Registration
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "staff")

        user = mongo.db.users.find_one({"username": username, "role": role})
        if user:
            stored = user.get("password", "")
            ok = False
            # If password looks like bcrypt hash
            if isinstance(stored, str) and (stored.startswith("$2b$") or stored.startswith("$2a$")):
                ok = bcrypt.check_password_hash(stored, password)
            else:
                # plaintext fallback (seed), then upgrade to hash
                if stored == password:
                    ok = True
                    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
                    mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"password": hashed}})

            if ok:
                session["user_id"] = str(user["_id"])
                session["username"] = user["username"]
                session["role"] = user["role"]
                if user["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("staff_dashboard"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form["email"].strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "staff")

        if mongo.db.users.find_one({"username": username}):
            return render_template("register.html", error="Username already taken")
        
        if mongo.db.users.find_one({"email": email}):
            return render_template("register.html", error="Email already registered")

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        mongo.db.users.insert_one({
            "username": username,
            "password": hashed,
            "role": role,
            "email": email
        })
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -----------------------
# OTP-based Forgot / Verify / Reset password flow
# -----------------------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        if not identifier:
            return render_template("forgot_password.html", error="Please provide username or email.")

        user = mongo.db.users.find_one({
            "$or": [
                {"username": identifier},
                {"email": identifier},
                {"email": {"$regex": f"^{identifier}$", "$options": "i"}}
            ]
        })

        generic_msg = "If an account exists, an OTP has been sent to the account's email (or displayed in server logs)."

        if not user:
            return render_template("forgot_password.html", message=generic_msg)

        otp = f"{random.randint(0, 999999):06d}"
        expires = datetime.utcnow() + timedelta(minutes=10)

        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"reset_otp": otp, "reset_otp_expires": expires}}
        )

        user_email = user.get("email")
        subject = "Your SmartStore OTP"
        body = f"Your password reset OTP is: {otp}\nIt is valid for 10 minutes."
        try:
            if user_email:
                send_email(user_email, subject, body)
            else:
                app.logger.info("User has no email; printing OTP to console")
                print("OTP for user", user.get("username"), "=", otp)
        except Exception:
            app.logger.exception("Failed sending OTP")

        return render_template("verify_otp.html", message="An OTP was sent. Enter it below to verify.", identifier=identifier)

    return render_template("forgot_password.html")

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        otp_entered = request.form.get("otp", "").strip()

        if not identifier or not otp_entered:
            return render_template("verify_otp.html", error="Please provide both identifier and OTP.", identifier=identifier)

        user = mongo.db.users.find_one({
            "$or": [
                {"username": identifier},
                {"email": identifier},
                {"email": {"$regex": f"^{identifier}$", "$options": "i"}}
            ]
        })

        generic_err = "Invalid OTP or expired. Request a new one."

        if not user:
            return render_template("verify_otp.html", error=generic_err)

        stored_otp = user.get("reset_otp")
        expires = user.get("reset_otp_expires")
        if not stored_otp or not expires:
            return render_template("verify_otp.html", error=generic_err)

        if expires < datetime.utcnow():
            mongo.db.users.update_one({"_id": user["_id"]}, {"$unset": {"reset_otp": "", "reset_otp_expires": ""}})
            return render_template("verify_otp.html", error="OTP expired. Please request a new OTP.")

        if otp_entered != stored_otp:
            return render_template("verify_otp.html", error="Invalid OTP. Please try again.", identifier=identifier)

        session["reset_user_id"] = str(user["_id"])
        session["reset_allowed_until"] = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        mongo.db.users.update_one({"_id": user["_id"]}, {"$unset": {"reset_otp": "", "reset_otp_expires": ""}})

        return redirect(url_for("reset_password"))

    identifier = request.args.get("identifier", "")
    return render_template("verify_otp.html", identifier=identifier)

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    uid = session.get("reset_user_id")
    allowed_until = session.get("reset_allowed_until")
    if not uid or not allowed_until:
        return redirect(url_for("forgot_password"))

    try:
        allowed_dt = datetime.fromisoformat(allowed_until)
    except Exception:
        session.pop("reset_user_id", None)
        session.pop("reset_allowed_until", None)
        return redirect(url_for("forgot_password"))

    if allowed_dt < datetime.utcnow():
        session.pop("reset_user_id", None)
        session.pop("reset_allowed_until", None)
        return redirect(url_for("forgot_password"))

    try:
        user = mongo.db.users.find_one({"_id": ObjectId(uid)})
    except Exception:
        session.pop("reset_user_id", None)
        session.pop("reset_allowed_until", None)
        return redirect(url_for("forgot_password"))

    if not user:
        session.pop("reset_user_id", None)
        session.pop("reset_allowed_until", None)
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        pw = request.form.get("password", "")
        pw2 = request.form.get("confirm_password", "")
        if not pw or not pw2:
            return render_template("reset_password.html", error="Please fill both password fields.")
        if pw != pw2:
            return render_template("reset_password.html", error="Passwords do not match.")

        hashed = bcrypt.generate_password_hash(pw).decode("utf-8")
        mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"password": hashed}, "$unset": {"reset_otp": "", "reset_otp_expires": ""}})
        session.pop("reset_user_id", None)
        session.pop("reset_allowed_until", None)
        return render_template("reset_password.html", info="Password updated successfully. You can now log in.")

    return render_template("reset_password.html")

# -----------------------------------
# The rest of your app (modified to include notifications)
# -----------------------------------
from datetime import datetime

@app.route("/admin")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    # Inventory stats
    items = list(mongo.db.items.find({}))
    total_items = len(items)
    total_units = sum(i.get("quantity", 0) for i in items)
    low_stock_alerts = sum(1 for i in items if i.get("quantity", 0) <= i.get("low_stock_threshold", 5))
    total_transactions = mongo.db.transactions.count_documents({})

    categories_set = set(i.get("category_name") for i in items if i.get("category_name"))
    categories = len(categories_set)

    category_docs = list(mongo.db.categories.find({}))
    category_names = [c.get("name") for c in category_docs]

    view_items = []
    for it in items:
        view_items.append({
            "id": str(it["_id"]),
            "name": it.get("name"),
            "quantity": it.get("quantity", 0),
            "price": it.get("price", 0.0),
            "category_name": it.get("category_name", "")
        })

    # ----------------------------
    # Notifications: last 5 transactions (resolve user & item names)
    # ----------------------------
    transaction_docs = list(
        mongo.db.transactions.find({}).sort("created_at", -1).limit(5)
    )

    notifications = []
    for t in transaction_docs:
        # resolve staff username
        staff_name = "Staff"
        try:
            uid = t.get("user_id")
            if isinstance(uid, ObjectId):
                u = mongo.db.users.find_one({"_id": uid})
                if u:
                    staff_name = u.get("username", "Staff")
            else:
                # maybe stored as string
                try:
                    u = mongo.db.users.find_one({"_id": ObjectId(uid)}) if uid else None
                    if u:
                        staff_name = u.get("username", "Staff")
                except Exception:
                    staff_name = t.get("performed_by") or t.get("staff_name") or "Staff"
        except Exception:
            staff_name = t.get("performed_by") or t.get("staff_name") or "Staff"

        # resolve item name
        item_name = t.get("item_name") or ""
        try:
            iid = t.get("item_id")
            if isinstance(iid, ObjectId):
                it = mongo.db.items.find_one({"_id": iid})
                if it:
                    item_name = it.get("name", item_name)
            else:
                try:
                    it = mongo.db.items.find_one({"_id": ObjectId(iid)}) if iid else None
                    if it:
                        item_name = it.get("name", item_name)
                except Exception:
                    pass
        except Exception:
            pass

        notif_type = t.get("type", "transaction")
        qty = t.get("quantity", 0)
        created = t.get("created_at", datetime.utcnow())
        notifications.append({
            "staff_name": staff_name,
            "action": notif_type,
            "item_name": item_name or "Unknown item",
            "quantity": qty,
            "timestamp": created
        })

    # unread notifications count from notifications collection
    try:
        unread_notifications = mongo.db.notifications.count_documents({"is_read": False})
    except Exception:
        unread_notifications = 0

    return render_template(
        "admin_dashboard.html",
        total_items=total_items,
        total_units=total_units,
        low_stock_alerts=low_stock_alerts,
        total_transactions=total_transactions,
        categories=categories,
        items=view_items,
        category_names=category_names,
        notifications=notifications,
        unread_notifications=unread_notifications
    )

@app.route("/staff")
def staff_dashboard():
    if session.get("role") not in ("staff", "admin"):
        return redirect(url_for("login"))

    items = list(mongo.db.items.find({}))
    total_items = len(items)
    total_units = sum(i.get("quantity", 0) for i in items)
    low_stock_items = sum(1 for i in items if i.get("quantity", 0) <= i.get("low_stock_threshold", 5))

    categories_set = set(i.get("category_name") for i in items if i.get("category_name"))
    categories = len(categories_set)

    category_docs = list(mongo.db.categories.find({}))
    category_names = sorted([c.get("name") for c in category_docs if c.get("name")])

    restock_requests = mongo.db.transactions.count_documents({"type": "restock_request"})

    view_items = []
    for it in items:
        view_items.append({
            "id": str(it["_id"]),
            "name": it.get("name"),
            "quantity": it.get("quantity", 0),
            "price": it.get("price", 0.0),
            "category_name": it.get("category_name", "")
        })

    # generate a short idempotency key to be used by the client for transaction requests
    tx_key = secrets.token_hex(16)
    try:
        session["_last_tx_key"] = tx_key
    except Exception:
        app.logger.exception("Could not write tx_key to session (non-fatal)")

    return render_template(
        "staff_dashboard.html",
        total_items=total_items,
        total_units=total_units,
        low_stock_items=low_stock_items,
        categories=categories,
        items=view_items,
        restock_requests=restock_requests,
        category_names=category_names,
        tx_key=tx_key
    )

# --- ADD ITEM (Admin only) ---
@app.route("/admin/items/add", methods=["GET", "POST"])
def add_item():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category_name = request.form.get("category_name", "").strip()

        existing_name = request.form.get("existing_name", "").strip()
        existing_category_name = request.form.get("existing_category_name", "").strip()

        if existing_name and not name:
            name = existing_name
        if existing_category_name and not category_name:
            category_name = existing_category_name

        quantity_raw = request.form.get("quantity", "0")
        price_raw = request.form.get("price", "0")
        low_stock_raw = request.form.get("low_stock_threshold", "5")

        try:
            quantity = int(quantity_raw)
        except ValueError:
            quantity = 0

        try:
            price = float(price_raw)
        except ValueError:
            price = 0.0

        try:
            low_stock_threshold = int(low_stock_raw)
        except ValueError:
            low_stock_threshold = 5

        category_id = None
        if category_name:
            existing_cat = mongo.db.categories.find_one({"name": category_name})
            if existing_cat:
                category_id = existing_cat["_id"]
            else:
                res = mongo.db.categories.insert_one({"name": category_name})
                category_id = res.inserted_id

        res = mongo.db.items.insert_one({
            "name": name,
            "category_name": category_name,
            "category_id": category_id,
            "quantity": quantity,
            "price": price,
            "low_stock_threshold": low_stock_threshold,
        })

        # Create notification for admins when a new item added
        create_notification(f"Item added: '{name}' (qty {quantity})", "item_added", {"item_id": str(res.inserted_id)})

        return redirect(url_for("admin_dashboard"))

    items = list(mongo.db.items.find({}))
    item_names = sorted({i.get("name") for i in items if i.get("name")})

    categories = list(mongo.db.categories.find({}))
    category_names = sorted({c.get("name") for c in categories if c.get("name")})

    return render_template(
        "add_item.html",
        item_names=item_names,
        category_names=category_names
    )

# --- Edit item (Admin only) ---
@app.route("/admin/items/<item_id>/edit", methods=["GET", "POST"])
def edit_item(item_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    try:
        oid = ObjectId(item_id)
    except Exception:
        return "Invalid item id", 400

    item = mongo.db.items.find_one({"_id": oid})
    if not item:
        return "Item not found", 404

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category_name = request.form.get("category_name", "").strip()
        quantity_raw = request.form.get("quantity", "0")
        price_raw = request.form.get("price", "0")
        low_stock_raw = request.form.get("low_stock_threshold", "5")

        try:
            quantity = int(quantity_raw)
        except ValueError:
            quantity = item.get("quantity", 0)

        try:
            price = float(price_raw)
        except ValueError:
            price = item.get("price", 0.0)

        try:
            low_stock_threshold = int(low_stock_raw)
        except ValueError:
            low_stock_threshold = item.get("low_stock_threshold", 5)

        category_id = item.get("category_id")
        if category_name:
            existing_cat = mongo.db.categories.find_one({"name": category_name})
            if existing_cat:
                category_id = existing_cat["_id"]
            else:
                res = mongo.db.categories.insert_one({"name": category_name})
                category_id = res.inserted_id

        update_data = {
            "name": name or item.get("name"),
            "category_name": category_name or item.get("category_name", ""),
            "category_id": category_id,
            "quantity": quantity,
            "price": price,
            "low_stock_threshold": low_stock_threshold,
        }

        mongo.db.items.update_one({"_id": oid}, {"$set": update_data})

        # Notification: item edited
        create_notification(f"Item edited: '{update_data['name']}' (qty {quantity})", "item_edited", {"item_id": str(item['_id'])})

        return redirect(url_for("admin_dashboard"))

    return render_template("edit_item.html", item=item, item_id=item_id)

# --- Delete item (Admin only) ---
@app.route("/admin/items/<item_id>/delete", methods=["POST"])
def delete_item(item_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    try:
        oid = ObjectId(item_id)
    except Exception:
        return "Invalid item id", 400

    item = mongo.db.items.find_one({"_id": oid})
    if item:
        mongo.db.items.delete_one({"_id": oid})
        create_notification(f"Item deleted: '{item.get('name')}'", "item_deleted", {"item_id": item_id})

    return redirect(url_for("admin_dashboard"))

# --- API endpoints (modified) ---
@app.route("/api/items")
def api_items():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    query = {}

    if q:
        query["name"] = {"$regex": q, "$options": "i"}
    if category and category.lower() != "all":
        query["category_name"] = category

    items = list(mongo.db.items.find(query))
    data = []
    for it in items:
        data.append({
            "id": str(it["_id"]),
            "name": it.get("name"),
            "quantity": it.get("quantity", 0),
            "price": it.get("price", 0.0),
            "category": it.get("category_name", "")
        })
    return jsonify(data)

@app.route("/api/transaction", methods=["POST"])
def api_transaction():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    payload = request.json or {}
    item_id = payload.get("item_id")
    t_type = payload.get("type")
    try:
        qty = int(payload.get("quantity", 0) or 0)
    except Exception:
        qty = 0
    recipient = payload.get("recipient")
    idemp_key = payload.get("idempotency_key") or payload.get("idempotencyKey")

    if not item_id:
        return jsonify({"error": "item_id is required"}), 400

    # If idempotency key provided, check whether we've already processed it for this user:
    if idemp_key:
        try:
            existing = mongo.db.transactions.find_one({"user_id": ObjectId(session["user_id"]), "idempotency_key": idemp_key})
            if existing:
                # Already processed: return current quantity (safe) and mark ok
                try:
                    oid_temp = ObjectId(item_id)
                    updated_item = mongo.db.items.find_one({"_id": oid_temp})
                    new_qty_safe = int(updated_item.get("quantity", 0)) if updated_item else None
                except Exception:
                    new_qty_safe = None
                return jsonify({"ok": True, "new_quantity": new_qty_safe, "idempotent": True})
        except Exception:
            app.logger.exception("Idempotency lookup failed; continuing processing")

    # store fingerprint & timestamp to session as a fallback dedupe
    try:
        session["_last_tx"] = {"fp": {"item_id": item_id, "type": t_type, "quantity": qty}, "ts": datetime.utcnow().isoformat()}
    except Exception:
        app.logger.exception("Could not write session _last_tx (non-fatal)")

    try:
        oid = ObjectId(item_id)
    except Exception:
        return jsonify({"error": "invalid item_id"}), 400

    item = mongo.db.items.find_one({"_id": oid})
    if not item:
        return jsonify({"error": "item not found"}), 404

    prev_qty = int(item.get("quantity", 0))
    low_threshold = int(item.get("low_stock_threshold", 5))

    # Perform atomic update depending on transaction type
    try:
        if t_type == "issue":
            if qty <= 0:
                return jsonify({"error": "quantity must be > 0"}), 400
            updated = mongo.db.items.find_one_and_update(
                {"_id": oid, "quantity": {"$gte": qty}},
                {"$inc": {"quantity": -qty}},
                return_document=ReturnDocument.AFTER
            )
            if not updated:
                return jsonify({"error": "not enough stock"}), 400
        elif t_type == "return":
            if qty <= 0:
                return jsonify({"error": "quantity must be > 0"}), 400
            updated = mongo.db.items.find_one_and_update(
                {"_id": oid},
                {"$inc": {"quantity": qty}},
                return_document=ReturnDocument.AFTER
            )
        elif t_type == "restock_request":
            # no quantity change
            updated = mongo.db.items.find_one({"_id": oid})
        else:
            return jsonify({"error": "invalid transaction type"}), 400

        # prepare transaction doc (include idempotency key if present)
        tx_doc = {
            "item_id": oid,
            "user_id": ObjectId(session["user_id"]),
            "type": t_type,
            "quantity": qty,
            "recipient_name": recipient,
            "created_at": datetime.utcnow()
        }
        if idemp_key:
            tx_doc["idempotency_key"] = idemp_key

        # Try insert. If idempotency unique index causes duplicate error, treat as already-processed.
        try:
            mongo.db.transactions.insert_one(tx_doc)
        except Exception as e:
            app.logger.warning("Transaction insert error (possible duplicate idempotency key): %s", e)
            updated_item = mongo.db.items.find_one({"_id": oid})
            return jsonify({"ok": True, "new_quantity": int(updated_item.get("quantity", 0))})

        # fetch updated item quantity
        new_qty = int(updated.get("quantity", 0))

        # create transaction notification
        uname = session.get("username", "unknown")
        create_notification(f"{uname} performed '{t_type}' on '{item.get('name')}' (qty {qty})", "transaction", {
            "item_id": item_id,
            "previous_qty": prev_qty,
            "new_qty": new_qty,
            "performed_by": uname
        })

        # create low-stock notification if threshold crossed (only when new_qty <= threshold and prev_qty > threshold)
        if new_qty <= low_threshold and prev_qty > low_threshold:
            create_notification(f"Low stock: '{item.get('name')}' is at {new_qty} units", "low_stock", {
                "item_id": item_id,
                "qty": new_qty
            })

        # for restock_request, create a separate notification
        if t_type == "restock_request":
            create_notification(f"Restock request: '{item.get('name')}' requested by {uname} (qty {qty})", "restock_request", {"item_id": item_id})

        return jsonify({"ok": True, "new_quantity": new_qty})
    except Exception:
        app.logger.exception("Transaction processing failed")
        return jsonify({"error": "internal error"}), 500

# --- Notifications API ---
@app.route("/api/notifications", methods=["GET"])
def api_get_notifications():
    # Only allow admins to fetch full notifications, staff can fetch their own in further enhancements
    # For simplicity, allow admins to fetch notifications; if not admin, return limited view
    role = session.get("role")
    docs = list(mongo.db.notifications.find({}).sort("created_at", -1).limit(50))
    notifications = []
    unread = 0
    for d in docs:
        is_read = bool(d.get("is_read", False))
        if not is_read:
            unread += 1
        created = d.get("created_at")
        created_str = created.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(created, datetime) else str(created)
        notifications.append({
            "id": str(d.get("_id")),
            "message": d.get("message"),
            "type": d.get("type"),
            "data": d.get("data", {}),
            "is_read": is_read,
            "created_at": created_str
        })
    return jsonify({"unread": unread, "notifications": notifications})

@app.route("/api/notifications/mark_read", methods=["POST"])
def api_notifications_mark_read():
    payload = request.get_json(silent=True) or {}
    nid = payload.get("id")
    if nid == "all":
        mongo.db.notifications.update_many({"is_read": False}, {"$set": {"is_read": True}})
        return jsonify({"ok": True})
    if not nid:
        return jsonify({"error": "id required"}), 400
    try:
        mongo.db.notifications.update_one({"_id": ObjectId(nid)}, {"$set": {"is_read": True}})
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"error": "invalid id"}), 400

# --- Reportlab PDF export  ---
@app.route("/admin/export/inventory")
def export_inventory_pdf():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    items = list(mongo.db.items.find({}))

    buffer = io.BytesIO()

    static_font_path = os.path.join(app.root_path, "static", "DejaVuSans.ttf")
    font_name = "Helvetica"

    if os.path.exists(static_font_path):
        try:
            pdfmetrics.registerFont(TTFont("DejaVuSans", static_font_path))
            font_name = "DejaVuSans"
        except Exception as e:
            print("Could not load DejaVuSans.ttf:", e)
    else:
        print("⚠️ DejaVuSans.ttf missing in /static folder")

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=30, rightMargin=30,
        topMargin=30, bottomMargin=30
    )
    styles = getSampleStyleSheet()
    story = []

    title_style = styles["Heading1"]
    title_style.fontName = font_name
    title_style.fontSize = 18
    story.append(Paragraph("Inventory Report - SmartStore DIEMS", title_style))
    story.append(Spacer(1, 6))

    meta_style = styles["Normal"]
    meta_style.fontName = font_name
    meta_style.fontSize = 9
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", meta_style))
    story.append(Spacer(1, 12))

    data = [["S/N", "Item Name", "Category", "Qty", "Price (₹)", "Status"]]

    for idx, it in enumerate(items, 1):
        qty = int(it.get("quantity", 0))
        low = int(it.get("low_stock_threshold", 5))

        if qty == 0:
            status = "Restock"
        elif qty <= low:
            status = "Low Stock"
        else:
            status = "In Stock"

        data.append([
            str(idx),
            it.get("name", ""),
            it.get("category_name", ""),
            str(qty),
            f"₹{float(it.get('price', 0.0)):,.2f}",
            status
        ])

    table = Table(
        data,
        colWidths=[20*mm, 60*mm, 35*mm, 15*mm, 25*mm, 30*mm]
    )

    tbl = TableStyle([
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2c3e50")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('ALIGN', (3,0), (4,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('TOPPADDING', (0,0), (-1,0), 8),
    ])

    for r in range(1, len(data)):
        status = data[r][5]

        if status == "Restock":
            bg = colors.HexColor("#f8d7da")
            tx = colors.HexColor("#721c24")
        elif status == "Low Stock":
            bg = colors.HexColor("#dbeafe")
            tx = colors.HexColor("#0b3d91")
        else:
            bg = colors.HexColor("#d4edda")
            tx = colors.HexColor("#155724")

        tbl.add('BACKGROUND', (5, r), (5, r), bg)
        tbl.add('TEXTCOLOR', (5, r), (5, r), tx)

        if r % 2 == 0:
            tbl.add('BACKGROUND', (0, r), (4, r), colors.HexColor("#fafbfc"))

    table.setStyle(tbl)

    story.append(table)
    story.append(Spacer(1, 12))

    total_items = len(items)
    total_units = sum(int(i.get("quantity",0)) for i in items)

    summary = Paragraph(
        f"<b>Total Items:</b> {total_items} &nbsp;&nbsp; "
        f"<b>Total Units:</b> {total_units}",
        meta_style
    )
    story.append(summary)

    doc.build(story)

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="inventory.pdf", mimetype="application/pdf")


@app.route("/admin/export/transactions")
def export_transactions_pdf():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    txs = list(mongo.db.transactions.find({}).sort("created_at", -1).limit(2000))
    buffer = io.BytesIO()

    static_font_path = os.path.join(app.root_path, "static", "DejaVuSans.ttf")
    font_name = "Helvetica"
    if os.path.exists(static_font_path):
        try:
            pdfmetrics.registerFont(TTFont("DejaVuSans", static_font_path))
            font_name = "DejaVuSans"
        except Exception:
            app.logger.exception("Could not load DejaVuSans.ttf — falling back to Helvetica")

    # Use landscape for more horizontal space
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=30, rightMargin=30,
        topMargin=30, bottomMargin=30
    )

    styles = getSampleStyleSheet()
    story = []

    title_style = styles["Heading1"]
    title_style.fontName = font_name
    title_style.fontSize = 16
    story.append(Paragraph("Transactions Report - SmartStore DIEMS", title_style))
    story.append(Spacer(1, 6))

    meta_style = styles["Normal"]
    meta_style.fontName = font_name
    meta_style.fontSize = 9
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", meta_style))
    story.append(Spacer(1, 8))

    # small paragraph style for table cells
    cell_style = ParagraphStyle(
        name="cell",
        fontName=font_name,
        fontSize=9,
        leading=11,
        allowWidows=True,
        allowOrphans=True,
    )

    # header row (use Paragraph to keep font consistent)
    data = [[
        Paragraph("<b>S/N</b>", cell_style),
        Paragraph("<b>Timestamp</b>", cell_style),
        Paragraph("<b>Staff</b>", cell_style),
        Paragraph("<b>Type</b>", cell_style),
        Paragraph("<b>Item</b>", cell_style),
        Paragraph("<b>Qty</b>", cell_style),
        Paragraph("<b>Recipient</b>", cell_style),
    ]]

    # fill rows
    for idx, tx in enumerate(txs, start=1):
        ts = tx.get("created_at")
        ts_str = ts.strftime("%Y-%m-%d %H:%M") if isinstance(ts, datetime) else str(ts)

        # resolve item name
        item_name = ""
        try:
            if tx.get("item_id"):
                item_doc = mongo.db.items.find_one({"_id": tx.get("item_id")})
                if item_doc:
                    item_name = item_doc.get("name", "")
        except Exception:
            item_name = tx.get("item_name") or ""

        # resolve staff name
        staff_name = ""
        try:
            if tx.get("user_id"):
                user_doc = mongo.db.users.find_one({"_id": tx.get("user_id")})
                if user_doc:
                    staff_name = user_doc.get("username", "")
        except Exception:
            staff_name = tx.get("performed_by") or ""

        tx_type = tx.get("type", "") or "-"
        qty = tx.get("quantity", 0)
        recipient = tx.get("recipient_name", "") or "-"

        data.append([
            Paragraph(str(idx), cell_style),
            Paragraph(ts_str, cell_style),
            Paragraph(staff_name or "-", cell_style),
            Paragraph(tx_type, cell_style),
            Paragraph(item_name or "-", cell_style),
            Paragraph(str(qty), cell_style),
            Paragraph(recipient, cell_style),
        ])

    # column widths (7 columns) - tuned for landscape page
    table_col_widths = [
        12 * mm,   # S/N
        36 * mm,   # Timestamp
        36 * mm,   # Staff
        28 * mm,   # Type
        120 * mm,  # Item (wide)
        15 * mm,   # Qty
        35 * mm,   # Recipient
    ]

    table = Table(data, colWidths=table_col_widths, repeatRows=1)

    # style similar to inventory report
    tbl = TableStyle([
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('FONTSIZE', (0,0), (-1,-1), 9),

        # header uses same color as inventory report
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#d4dfea")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),

        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('ALIGN', (5,0), (5,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.25, colors.grey),

        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('TOPPADDING', (0,0), (-1,0), 8),
    ])

    # alternating row backgrounds (light stripe like inventory)
    for r in range(1, len(data)):
        if r % 2 == 0:
            tbl.add('BACKGROUND', (0, r), (-1, r), colors.HexColor("#fafbfc"))

    table.setStyle(tbl)

    story.append(table)
    story.append(Spacer(1, 12))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="transactions.pdf", mimetype="application/pdf")



if __name__ == "__main__":
    app.secret_key = app.config.get("SECRET_KEY", "dev-secret")
    app.run(debug=True)
