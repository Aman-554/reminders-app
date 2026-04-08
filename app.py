import osimport os
from flask import Flask, redirect, url_for, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

# -----error handling---------------------
def error_response(message, code=400):
    return jsonify({
        "success": False,
        "error": message
    }), code

def success_response(data=None, code=200):
    return jsonify({
        "success": True,
        "data": data
    }), code

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")

# ── Database ──────────────────────────────────────────────────────────────────
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///reminders.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REMEMBER_COOKIE_DURATION"] = 60 * 60 * 24 * 7   # 7 days
db = SQLAlchemy(app)

# ── Flask-Login ───────────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── Models ────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lists = db.relationship("List", backref="owner", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(30), default="primary")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    todos = db.relationship("Todo", backref="list", lazy=True, cascade="all, delete-orphan")


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey("list.id"), nullable=False)
    title = db.Column(db.String(300), nullable=False)
    note = db.Column(db.String(500), default="")
    done = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=True)
    priority = db.Column(db.String(20), default="medium")  # low, medium, high

    def to_dict(self):
        return {
            "id": self.id,
            "list_id": self.list_id,
            "title": self.title,
            "note": self.note,
            "done": self.done,
            "created_at": self.created_at.strftime("%d %b %Y"),
            "due_date": self.due_date.strftime("%Y-%m-%d %H:%M") if self.due_date else None,
            "priority": self.priority or "medium"
        }


# ── Scheduler Setup ──────────────────────────────────────────────────────────
scheduler = BackgroundScheduler()

def check_due_reminders():
    """Check for due reminders and mark them for notification"""
    with app.app_context():
        now = datetime.utcnow()
        
        # Find todos that are due, not done, and haven't been notified recently
        todos = Todo.query.filter(
            Todo.due_date != None,
            Todo.due_date <= now,
            Todo.done == False
        ).all()
        
        for todo in todos:
            # Log reminder (frontend will poll for these)
            print(f"[REMINDER] Todo #{todo.id}: '{todo.title}' is due!")

# Schedule the job to run every minute
scheduler.add_job(check_due_reminders, 'interval', minutes=1)
scheduler.start()

# Shutdown scheduler on app exit
atexit.register(lambda: scheduler.shutdown())

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    return render_template("app.html", user=current_user)

# ── Sign Up ───────────────────────────────────────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    errors = {}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username:
            errors["username"] = "Username is required."
        elif len(username) < 3:
            errors["username"] = "Username must be at least 3 characters."
        elif len(username) > 30:
            errors["username"] = "Username must be 30 characters or less."
        elif not username.isalnum() and "_" not in username:
            errors["username"] = "Only letters, numbers and underscores allowed."
        elif User.query.filter_by(username=username).first():
            errors["username"] = "That username is already taken."

        if not password:
            errors["password"] = "Password is required."
        elif len(password) < 6:
            errors["password"] = "Password must be at least 6 characters."

        if not errors:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            for list_name, color in [("Today", "danger"), ("Work", "primary"), ("Personal", "success")]:
                db.session.add(List(user_id=user.id, name=list_name, color=color))
            db.session.commit()

            login_user(user)
            return redirect(url_for("index"))

    return render_template("signup.html", errors=errors, form=request.form)

# ── Sign In ───────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember_me = request.form.get("remember_me") == "on"

        user = User.query.filter_by(username=username).first()

        if not username or not password:
            error = "Please enter your username and password."
        elif not user or not user.check_password(password):
            error = "Incorrect username or password."
        else:
            login_user(user, remember=remember_me)
            return redirect(url_for("index"))

    return render_template("login.html", error=error, form=request.form)

# ── Sign Out ──────────────────────────────────────────────────────────────────
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ── Reminders API ────────────────────────────────────────────────────────────
@app.route("/reminders/due", methods=["GET"])
@login_required
def get_due_reminders():
    """Get all due reminders for the current user"""
    now = datetime.utcnow()
    
    # Get all lists belonging to the user
    user_list_ids = [lst.id for lst in current_user.lists]
    
    # Find due todos
    due_todos = Todo.query.filter(
        Todo.list_id.in_(user_list_ids),
        Todo.due_date != None,
        Todo.due_date <= now,
        Todo.done == False
    ).all()
    
    return success_response({
        "reminders": [todo.to_dict() for todo in due_todos]
    })

# ── Lists API ─────────────────────────────────────────────────────────────────
@app.route("/lists", methods=["GET"])
@login_required
def get_lists():
    result = []
    for l in current_user.lists:
        pending = sum(1 for t in l.todos if not t.done)
        result.append({"id": l.id, "name": l.name, "color": l.color, "pending": pending})
    return success_response({"lists": result})

@app.route("/lists", methods=["POST"])
@login_required
def create_list():
    data = request.get_json()
    if not data or not data.get("name", "").strip():
        return error_response("Name required")
    lst = List(user_id=current_user.id, name=data["name"].strip(), color=data.get("color", "primary"))
    db.session.add(lst)
    db.session.commit()
    return success_response({"id": lst.id, "name": lst.name, "color": lst.color}, 201)

@app.route("/lists/<int:lid>", methods=["GET"])
@login_required
def get_list(lid):
    lst = List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    return success_response({
        "id": lst.id,
        "name": lst.name,
        "color": lst.color
    })

@app.route("/lists/<int:lid>", methods=["PUT"])
@login_required
def update_list(lid):
    lst = List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    data = request.get_json()
    if data.get("name", "").strip():
        lst.name = data["name"].strip()
    if data.get("color", "").strip():
        lst.color = data["color"].strip()
    db.session.commit()
    return success_response({
        "id": lst.id,
        "name": lst.name,
        "color": lst.color
    })

@app.route("/lists/<int:lid>", methods=["DELETE"])
@login_required
def delete_list(lid):
    lst = List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    db.session.delete(lst)
    db.session.commit()
    return success_response({"message": "Deleted"})

# ── Todos API ─────────────────────────────────────────────────────────────────
@app.route("/lists/<int:lid>/todos", methods=["GET"])
@login_required
def get_todos(lid):
    List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    todos = Todo.query.filter_by(list_id=lid).order_by(Todo.created_at).all()
    return success_response({
        "todos": [t.to_dict() for t in todos]
    })

@app.route("/lists/<int:lid>/todos", methods=["POST"])
@login_required
def create_todo(lid):
    List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    data = request.get_json()

    if not data or not data.get("title", "").strip():
        return error_response("Title required")

    due_date_str = data.get("due_date")
    due_date = None
    if due_date_str:
        try:
            due_date = datetime.fromisoformat(due_date_str)
        except:
            return error_response("Invalid date format")

    priority = data.get("priority", "medium")
    if priority not in ["low", "medium", "high"]:
        priority = "medium"

    todo = Todo(
        list_id=lid,
        title=data["title"].strip(),
        note=data.get("note", ""),
        due_date=due_date,
        priority=priority
    )

    db.session.add(todo)
    db.session.commit()

    return success_response(todo.to_dict(), 201)

@app.route("/todos/<int:tid>", methods=["GET"])
@login_required
def get_todo(tid):
    todo = Todo.query.get_or_404(tid)
    List.query.filter_by(id=todo.list_id, user_id=current_user.id).first_or_404()
    return success_response(todo.to_dict())

@app.route("/todos/<int:tid>", methods=["PUT"])
@login_required
def update_todo(tid):
    todo = Todo.query.get_or_404(tid)
    List.query.filter_by(id=todo.list_id, user_id=current_user.id).first_or_404()
    data = request.get_json()
    
    if data.get("title", "").strip():
        todo.title = data["title"].strip()
    if "note" in data:
        todo.note = data["note"]
    if "done" in data:
        todo.done = bool(data["done"])
    if "priority" in data and data["priority"] in ["low", "medium", "high"]:
        todo.priority = data["priority"]
    
    db.session.commit()
    return success_response(todo.to_dict())

@app.route("/todos/<int:tid>/toggle", methods=["PATCH"])
@login_required
def toggle_todo(tid):
    todo = Todo.query.get_or_404(tid)
    List.query.filter_by(id=todo.list_id, user_id=current_user.id).first_or_404()
    todo.done = not todo.done
    db.session.commit()
    return success_response(todo.to_dict())

@app.route("/todos/<int:tid>", methods=["DELETE"])
@login_required
def delete_todo(tid):
    todo = Todo.query.get_or_404(tid)
    List.query.filter_by(id=todo.list_id, user_id=current_user.id).first_or_404()
    db.session.delete(todo)
    db.session.commit()
    return success_response({"message": "Deleted"})

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        db.drop_all()  # Remove this line after first run to preserve data
        db.create_all()
    app.run(debug=True, port=5000)
from flask import Flask, redirect, url_for, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")

# ── Database ──────────────────────────────────────────────────────────────────
app.config["SQLALCHEMY_DATABASE_URI"]        = "sqlite:///reminders.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REMEMBER_COOKIE_DURATION"]       = 60 * 60 * 24 * 7   # 7 days
db = SQLAlchemy(app)

# ── Flask-Login ───────────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── Models ────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    lists         = db.relationship("List", backref="owner", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class List(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name       = db.Column(db.String(100), nullable=False)
    color      = db.Column(db.String(30), default="primary")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    todos      = db.relationship("Todo", backref="list", lazy=True, cascade="all, delete-orphan")


class Todo(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    list_id    = db.Column(db.Integer, db.ForeignKey("list.id"), nullable=False)
    title      = db.Column(db.String(300), nullable=False)
    note       = db.Column(db.String(500), default="")
    done       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":         self.id,
            "list_id":    self.list_id,
            "title":      self.title,
            "note":       self.note,
            "done":       self.done,
            "created_at": self.created_at.strftime("%d %b %Y"),
        }


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("app.html", user=current_user)


# ── Sign Up ───────────────────────────────────────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    errors = {}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Validate username
        if not username:
            errors["username"] = "Username is required."
        elif len(username) < 3:
            errors["username"] = "Username must be at least 3 characters."
        elif len(username) > 30:
            errors["username"] = "Username must be 30 characters or less."
        elif not username.isalnum() and "_" not in username:
            errors["username"] = "Only letters, numbers and underscores allowed."
        elif User.query.filter_by(username=username).first():
            errors["username"] = "That username is already taken."

        # Validate password
        if not password:
            errors["password"] = "Password is required."
        elif len(password) < 6:
            errors["password"] = "Password must be at least 6 characters."

        if not errors:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            # Seed default lists for new user
            for list_name, color in [("Today", "danger"), ("Work", "primary"), ("Personal", "success")]:
                db.session.add(List(user_id=user.id, name=list_name, color=color))
            db.session.commit()

            login_user(user)
            return redirect(url_for("index"))

    return render_template("signup.html", errors=errors, form=request.form)


# ── Sign In ───────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        username    = request.form.get("username", "").strip()
        password    = request.form.get("password", "")
        remember_me = request.form.get("remember_me") == "on"

        user = User.query.filter_by(username=username).first()

        if not username or not password:
            error = "Please enter your username and password."
        elif not user or not user.check_password(password):
            error = "Incorrect username or password."
        else:
            login_user(user, remember=remember_me)
            return redirect(url_for("index"))

    return render_template("login.html", error=error, form=request.form)


# ── Sign Out ──────────────────────────────────────────────────────────────────
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ── Lists API ─────────────────────────────────────────────────────────────────

@app.route("/lists", methods=["GET"])
@login_required
def get_lists():
    result = []
    for l in current_user.lists:
        pending = sum(1 for t in l.todos if not t.done)
        result.append({"id": l.id, "name": l.name, "color": l.color, "pending": pending})
    return jsonify({"lists": result})


@app.route("/lists", methods=["POST"])
@login_required
def create_list():
    data = request.get_json()
    if not data or not data.get("name", "").strip():
        return jsonify({"error": "Name required"}), 400
    lst = List(user_id=current_user.id, name=data["name"].strip(), color=data.get("color", "primary"))
    db.session.add(lst)
    db.session.commit()
    return jsonify({"id": lst.id, "name": lst.name, "color": lst.color}), 201


@app.route("/lists/<int:lid>", methods=["GET"])
@login_required
def get_list(lid):
    lst = List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    return jsonify({"id": lst.id, "name": lst.name, "color": lst.color})


@app.route("/lists/<int:lid>", methods=["PUT"])
@login_required
def update_list(lid):
    lst  = List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    data = request.get_json()
    if data.get("name", "").strip():
        lst.name = data["name"].strip()
    if data.get("color", "").strip():
        lst.color = data["color"].strip()
    db.session.commit()
    return jsonify({"id": lst.id, "name": lst.name, "color": lst.color})


@app.route("/lists/<int:lid>", methods=["DELETE"])
@login_required
def delete_list(lid):
    lst = List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    db.session.delete(lst)
    db.session.commit()
    return jsonify({"message": "Deleted"})


# ── Todos API ─────────────────────────────────────────────────────────────────

@app.route("/lists/<int:lid>/todos", methods=["GET"])
@login_required
def get_todos(lid):
    List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    todos = Todo.query.filter_by(list_id=lid).order_by(Todo.created_at).all()
    return jsonify({"todos": [t.to_dict() for t in todos]})


@app.route("/lists/<int:lid>/todos", methods=["POST"])
@login_required
def create_todo(lid):
    List.query.filter_by(id=lid, user_id=current_user.id).first_or_404()
    data = request.get_json()
    if not data or not data.get("title", "").strip():
        return jsonify({"error": "Title required"}), 400
    todo = Todo(list_id=lid, title=data["title"].strip(), note=data.get("note", ""))
    db.session.add(todo)
    db.session.commit()
    return jsonify(todo.to_dict()), 201


@app.route("/todos/<int:tid>", methods=["GET"])
@login_required
def get_todo(tid):
    todo = Todo.query.get_or_404(tid)
    List.query.filter_by(id=todo.list_id, user_id=current_user.id).first_or_404()
    return jsonify(todo.to_dict())


@app.route("/todos/<int:tid>", methods=["PUT"])
@login_required
def update_todo(tid):
    todo = Todo.query.get_or_404(tid)
    List.query.filter_by(id=todo.list_id, user_id=current_user.id).first_or_404()
    data = request.get_json()
    if data.get("title", "").strip():
        todo.title = data["title"].strip()
    if "note" in data:
        todo.note = data["note"]
    if "done" in data:
        todo.done = bool(data["done"])
    db.session.commit()
    return jsonify(todo.to_dict())


@app.route("/todos/<int:tid>/toggle", methods=["PATCH"])
@login_required
def toggle_todo(tid):
    todo = Todo.query.get_or_404(tid)
    List.query.filter_by(id=todo.list_id, user_id=current_user.id).first_or_404()
    todo.done = not todo.done
    db.session.commit()
    return jsonify(todo.to_dict())


@app.route("/todos/<int:tid>", methods=["DELETE"])
@login_required
def delete_todo(tid):
    todo = Todo.query.get_or_404(tid)
    List.query.filter_by(id=todo.list_id, user_id=current_user.id).first_or_404()
    db.session.delete(todo)
    db.session.commit()
    return jsonify({"message": "Deleted"})


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
