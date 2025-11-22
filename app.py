from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from config import Config
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io

app = Flask(__name__)
app.config.from_object(Config)

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Helpers
def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return mongo.db.users.find_one({"_id": ObjectId(uid)})

# --- Auth routes ---
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "staff")

        user = mongo.db.users.find_one({"username": username, "role": role})
        if user:
            stored = user.get("password", "")
            ok = False
            # If password looks like a bcrypt hash
            if stored.startswith("$2b$") or stored.startswith("$2a$"):
                ok = bcrypt.check_password_hash(stored, password)
            else:
                # plaintext fallback (from seed), then upgrade to hash
                if stored == password:
                    ok = True
                    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
                    mongo.db.users.update_one(
                        {"_id": user["_id"]},
                        {"$set": {"password": hashed}}
                    )

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
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "staff")

        if mongo.db.users.find_one({"username": username}):
            return render_template("register.html", error="Username already taken")

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        mongo.db.users.insert_one({
            "username": username,
            "password": hashed,
            "role": role
        })
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    # All items
    items = list(mongo.db.items.find({}))

    total_items = len(items)
    total_units = sum(i.get("quantity", 0) for i in items)
    low_stock_alerts = sum(
        1 for i in items if i.get("quantity", 0) <= i.get("low_stock_threshold", 5)
    )
    total_transactions = mongo.db.transactions.count_documents({})

    # Categories from items (for count)
    categories_set = set(i.get("category_name") for i in items if i.get("category_name"))
    categories = len(categories_set)

    # 🔹 NEW: get distinct category names from categories collection for dropdowns
    category_docs = list(mongo.db.categories.find({}))
    category_names = [c.get("name") for c in category_docs]

    # Build view items list
    view_items = []
    for it in items:
        view_items.append({
            "id": str(it["_id"]),
            "name": it.get("name"),
            "quantity": it.get("quantity", 0),
            "price": it.get("price", 0.0),
            "category_name": it.get("category_name", "")
        })

    return render_template(
        "admin_dashboard.html",
        total_items=total_items,
        total_units=total_units,
        low_stock_alerts=low_stock_alerts,
        total_transactions=total_transactions,
        categories=categories,
        items=view_items,
        category_names=category_names,   # 🔹 pass to template
    )


@app.route("/staff")
def staff_dashboard():
    if session.get("role") not in ("staff", "admin"):
        return redirect(url_for("login"))

    items = list(mongo.db.items.find({}))
    total_items = len(items)
    total_units = sum(i.get("quantity", 0) for i in items)
    low_stock_items = sum(
        1 for i in items if i.get("quantity", 0) <= i.get("low_stock_threshold", 5)
    )
    categories_set = set(i.get("category_name") for i in items if i.get("category_name"))
    categories = len(categories_set)
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

    return render_template(
        "staff_dashboard.html",
        total_items=total_items,
        total_units=total_units,
        low_stock_items=low_stock_items,
        categories=categories,
        items=view_items,
        restock_requests=restock_requests
    )

# --- ADD ITEM (Admin only) ---
@app.route("/admin/items/add", methods=["GET", "POST"])
def add_item():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        # From text inputs
        name = request.form.get("name", "").strip()
        category_name = request.form.get("category_name", "").strip()

        # From dropdowns (existing items / categories)
        existing_name = request.form.get("existing_name", "").strip()
        existing_category_name = request.form.get("existing_category_name", "").strip()

        # Prefer dropdown values if provided and text field is empty
        if existing_name and not name:
            name = existing_name
        if existing_category_name and not category_name:
            category_name = existing_category_name

        quantity_raw = request.form.get("quantity", "0")
        price_raw = request.form.get("price", "0")
        low_stock_raw = request.form.get("low_stock_threshold", "5")

        # Parse numbers safely
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

        # --- Ensure category exists in categories collection ---
        category_id = None
        if category_name:
            existing_cat = mongo.db.categories.find_one({"name": category_name})
            if existing_cat:
                category_id = existing_cat["_id"]
            else:
                res = mongo.db.categories.insert_one({"name": category_name})
                category_id = res.inserted_id

        # Insert item into items collection
        mongo.db.items.insert_one({
            "name": name,
            "category_name": category_name,
            "category_id": category_id,   # reference to categories collection
            "quantity": quantity,
            "price": price,
            "low_stock_threshold": low_stock_threshold,
        })

        return redirect(url_for("admin_dashboard"))

    # GET: show add_item page with dropdowns populated
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

        # Keep categories collection in sync when editing category name
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
        return redirect(url_for("admin_dashboard"))

    # GET: show edit form
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

    mongo.db.items.delete_one({"_id": oid})
    # optionally also remove its transactions:
    # mongo.db.transactions.delete_many({"item_id": oid})
    return redirect(url_for("admin_dashboard"))

# --- API ---
@app.route("/api/items")
def api_items():
    q = request.args.get("q", "")
    query = {}
    if q:
        query["name"] = {"$regex": q, "$options": "i"}
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
    qty = int(payload.get("quantity", 0) or 0)
    recipient = payload.get("recipient")

    if not item_id:
        return jsonify({"error": "item_id is required"}), 400

    try:
        oid = ObjectId(item_id)
    except Exception:
        return jsonify({"error": "invalid item_id"}), 400

    item = mongo.db.items.find_one({"_id": oid})
    if not item:
        return jsonify({"error": "item not found"}), 404

    if t_type == "issue":
        if item.get("quantity", 0) < qty:
            return jsonify({"error": "not enough stock"}), 400
        mongo.db.items.update_one({"_id": oid}, {"$inc": {"quantity": -qty}})
    elif t_type == "return":
        mongo.db.items.update_one({"_id": oid}, {"$inc": {"quantity": qty}})
    elif t_type == "restock_request":
        pass

    mongo.db.transactions.insert_one({
        "item_id": oid,
        "user_id": ObjectId(session["user_id"]),
        "type": t_type,
        "quantity": qty,
        "recipient_name": recipient,
        "created_at": datetime.utcnow(),
    })
    return jsonify({"ok": True})

# --- PDF Export with reportlab ---
@app.route("/admin/export/inventory")
def export_inventory_pdf():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    items = list(mongo.db.items.find({}))

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50

    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, y, "Inventory Report - SmartStore DIEMS")
    y -= 30
    p.setFont("Helvetica", 10)

    for it in items:
        line = f"{it.get('name')} | {it.get('category_name','')} | Qty: {it.get('quantity',0)} | Price: {it.get('price',0.0)}"
        p.drawString(50, y, line)
        y -= 15
        if y < 50:
            p.showPage()
            y = height - 50

    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="inventory.pdf", mimetype="application/pdf")

if __name__ == "__main__":
    app.secret_key = app.config["SECRET_KEY"]
    app.run(debug=True)
