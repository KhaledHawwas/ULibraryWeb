from functools import wraps
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify

from domin import valid_level
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import constants
from utils import apology


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


# Configure application
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL(f"sqlite:///{constants.DATABASE_NAME}")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@login_required
@app.route('/toggle-star/<int:item_id>', methods=['POST'])
def toggle_star(item_id):
    data = request.get_json()
    stared = db.execute("SELECT * FROM stars WHERE userId = ? AND itemId = ?", session["user_id"], item_id)
    if len(stared) == 0:
        db.execute("INSERT INTO stars (userId, itemId) VALUES (?, ?)", session["user_id"], item_id)
    else:
        db.execute("DELETE FROM stars WHERE userId = ? AND itemId = ?", session["user_id"], item_id)
    return jsonify(success=True)


@login_required
@app.route("/toggle-downloads/<int:item_id>", methods=["POST"])
def toggle_downloads(item_id):
    downloads = db.execute("SELECT * FROM items WHERE id = ?", item_id)[0]["downloads"]
    db.execute("UPDATE items SET downloads = ? WHERE id = ?", downloads + 1, item_id)
    return jsonify(success=True)

@app.route("/")
def index():
    return render_template("index.html")


@login_required
@app.route("/subjects", methods=["GET"])
def subjects():
    subjects = db.execute("SELECT * FROM subjects where level=?", session["level"])
    return render_template("subjects.html", subjects=subjects)


@login_required
@app.route('/items', methods=["GET", "POST"])
def items():
    selected_items = []
    if request.method == "GET":
        selected_items = db.execute("SELECT * FROM items")
    if request.method == "POST":
        name = request.form.get("subjectName")
        if not name:
            return apology("must provide name", 400)
        print(name)
        selected_items = db.execute("SELECT * FROM items where subjectName = ?", name)

    stared_items = db.execute("SELECT * FROM stars where userId = ?", session["user_id"])
    for item in selected_items:
        item["stared"] = False
        for stared_item in stared_items:
            if item["id"] == stared_item["itemId"]:
                item["stared"] = True
    return render_template("items.html", items=selected_items)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
                rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["level"] = rows[0]["level"]

        # Redirect user to home page
        flash("You were successfully logged in")
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("register.html")
    in_pass = request.form.get("password")
    in_user = request.form.get("username")
    in_level = request.form.get("level")

    if not in_user:
        return apology("must provide username", 400)

    if not in_pass:
        return apology("must provide password", 400)
    if in_pass != request.form.get("confirmation"):
        return apology("passwords do not match", 400)
    if not in_level and valid_level(in_level):
        return apology("must provide level", 400)

    # Query database for username
    rows = db.execute(
        "SELECT * FROM users WHERE username = ?", in_user
    )

    if len(rows) != 0:
        return apology("user name exists before", 400)
    hashed_password = generate_password_hash(in_pass)
    username = in_user
    db.execute("""
    INSERT INTO users (username, hash,level)
    VALUES (?, ?, ?)
    """, username, hashed_password, in_level)
    rows = db.execute(
        "SELECT * FROM users WHERE username = ?", in_user
    )
    session["user_id"] = rows[0]["id"]
    session["level"] = rows[0]["level"]
    flash("You were successfully registered")
    return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
