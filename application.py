import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///list.db")

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods =["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        if not request.form.get("comp"):
            return render_template("error.html")
        id_c = request.form.get("comp")
        
        db.execute("INSERT INTO completed (task, user_id) SELECT task, user_id FROM tasks WHERE id = (?)", 
        id_c)
        
        db.execute("DELETE FROM tasks WHERE id = (?)", id_c)
        
        flash("Completed!")
        return redirect("/")
    else:
        tasks = db.execute("SELECT id, task, date FROM tasks WHERE user_id = (?)", session["user_id"])
        return render_template("index.html", tasks=tasks)
        
@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":

        if not request.form.get("task"):
            return render_template("error.html")

        if not request.form.get("month"):
            return render_template("error.html")
            
        if not request.form.get("day"):
            return render_template("error.html")
        
        month = int(request.form.get("month"))
        day = int(request.form.get("day"))
        
        if month > 12 or month < 1:
             return render_template("error.html")
            
        if day < 1 or day > 31:
            return render_template("error.html")
            
        monthS = str(month)
        dayS = str(day)
        date = (f"{monthS}/{dayS}")
        
        db.execute("INSERT INTO tasks (user_id, task, date) VALUES(?, ?, ?)", 
        session["user_id"], request.form.get("task"), date)
        
        flash("Created!")
        return redirect("/")
    else:
        return render_template("create.html")

@app.route("/completed")
@login_required
def completed():
    completed_tasks = db.execute("SELECT id, task, date_c FROM completed WHERE user_id = (?)", 
    session["user_id"])
    return render_template("completed.html", completed_tasks=completed_tasks)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    session.clear()

    if request.method == "POST":

        if not request.form.get("username"):
            return render_template("error.html")

        elif not request.form.get("password"):
            return render_template("error.html")

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("error.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")
        
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("error.html")

        elif not request.form.get("confirmation"):
            return render_template("error.html")
            
        if request.form.get("password") != request.form.get("confirmation"):
            return render_template("error.html")

       
        key = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"),
        generate_password_hash(request.form.get("password")))
        
        session["user_id"] = key

        return redirect("/")

    else:
        return render_template("register.html")
        
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")