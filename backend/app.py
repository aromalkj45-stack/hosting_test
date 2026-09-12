
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# ---------------------------------------------------
# SECRET KEY FOR SESSIONS
# ---------------------------------------------------

# For production, store this in a Render environment variable.
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "my-secret-key-change-this"
)


# ---------------------------------------------------
# DATABASE PATH
# ---------------------------------------------------

# Get the directory where this app.py file is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# SQLite database will be created inside the backend folder
DATABASE = os.path.join(BASE_DIR, "database.db")


# ---------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------

def get_db_connection():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# ---------------------------------------------------
# CREATE DATABASE AND USERS TABLE
# ---------------------------------------------------

def create_database():

    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()

    connection.close()


# ---------------------------------------------------
# INITIALIZE DATABASE
# ---------------------------------------------------

# IMPORTANT:
# This must run when the application starts.
#
# Previously this was inside:
#
# if __name__ == "__main__":
#
# That does not run when Render starts the application
# using Gunicorn.

create_database()


# ---------------------------------------------------
# HOME / ROOT
# ---------------------------------------------------

@app.route("/")
def index():

    if "user_id" in session:

        return redirect(url_for("home"))

    return redirect(url_for("login"))


# ---------------------------------------------------
# LOGIN
# ---------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # ---------------------------------------------
        # CHECK EMPTY FIELDS
        # ---------------------------------------------

        if not username or not password:

            flash(
                "Please enter username and password.",
                "error"
            )

            return redirect(url_for("login"))

        # ---------------------------------------------
        # FIND USER
        # ---------------------------------------------

        connection = get_db_connection()

        user = connection.execute(
            """
            SELECT * FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        # ---------------------------------------------
        # CHECK USER AND PASSWORD
        # ---------------------------------------------

        if user and check_password_hash(
            user["password"],
            password
        ):

            # Store user information in session
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash(
                "Login successful!",
                "success"
            )

            return redirect(url_for("home"))

        else:

            flash(
                "Invalid username or password.",
                "error"
            )

            return redirect(url_for("login"))

    return render_template("login.html")


# ---------------------------------------------------
# REGISTER
# ---------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ---------------------------------------------
        # VALIDATION
        # ---------------------------------------------

        if (
            not username
            or not email
            or not password
            or not confirm_password
        ):

            flash(
                "Please fill in all fields.",
                "error"
            )

            return redirect(url_for("register"))

        # ---------------------------------------------
        # CHECK PASSWORD LENGTH
        # ---------------------------------------------

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "error"
            )

            return redirect(url_for("register"))

        # ---------------------------------------------
        # CHECK PASSWORD CONFIRMATION
        # ---------------------------------------------

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(url_for("register"))

        # ---------------------------------------------
        # CHECK EXISTING USER
        # ---------------------------------------------

        connection = get_db_connection()

        existing_user = connection.execute(
            """
            SELECT * FROM users
            WHERE username = ? OR email = ?
            """,
            (username, email)
        ).fetchone()

        if existing_user:

            connection.close()

            flash(
                "Username or email already exists.",
                "error"
            )

            return redirect(url_for("register"))

        # ---------------------------------------------
        # HASH PASSWORD
        # ---------------------------------------------

        password_hash = generate_password_hash(password)

        # ---------------------------------------------
        # INSERT USER
        # ---------------------------------------------

        connection.execute(
            """
            INSERT INTO users
            (username, email, password)
            VALUES (?, ?, ?)
            """,
            (
                username,
                email,
                password_hash
            )
        )

        connection.commit()

        connection.close()

        flash(
            "Registration successful! Please login.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------------------------------------------
# HOME PAGE
# ---------------------------------------------------

@app.route("/home")
def home():

    # ---------------------------------------------
    # CHECK LOGIN
    # ---------------------------------------------

    if "user_id" not in session:

        flash(
            "Please login first.",
            "error"
        )

        return redirect(url_for("login"))

    # ---------------------------------------------
    # SHOW HOME PAGE
    # ---------------------------------------------

    return render_template(
        "home.html",
        username=session["username"]
    )


# ---------------------------------------------------
# LOGOUT
# ---------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))


# ---------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )
