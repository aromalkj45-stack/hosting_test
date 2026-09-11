from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# Secret key for sessions
app.secret_key = "my-secret-key-change-this"


# ---------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------

def get_db_connection():
    connection = sqlite3.connect("database.db")
    connection.row_factory = sqlite3.Row
    return connection


# ---------------------------------------------------
# CREATE DATABASE
# ---------------------------------------------------

def create_database():

    connection = get_db_connection()

    cursor = connection.cursor()

    cursor.execute("""
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

        # Check empty fields
        if not username or not password:

            flash("Please enter username and password.", "error")

            return redirect(url_for("login"))

        connection = get_db_connection()

        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        connection.close()

        # Check user and password
        if user and check_password_hash(user["password"], password):

            # Store user information in session
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login successful!", "success")

            return redirect(url_for("home"))

        else:

            flash("Invalid username or password.", "error")

            return redirect(url_for("login"))

    return render_template("login.html")


# ---------------------------------------------------
# REGISTER
# ---------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # ---------------------------------------------
        # VALIDATION
        # ---------------------------------------------

        if not username or not email or not password or not confirm_password:

            flash("Please fill in all fields.", "error")

            return redirect(url_for("register"))

        # Check password length

        if len(password) < 6:

            flash("Password must contain at least 6 characters.", "error")

            return redirect(url_for("register"))

        # Check password confirmation

        if password != confirm_password:

            flash("Passwords do not match.", "error")

            return redirect(url_for("register"))

        # ---------------------------------------------
        # CHECK EXISTING USER
        # ---------------------------------------------

        connection = get_db_connection()

        existing_user = connection.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()

        if existing_user:

            connection.close()

            flash("Username or email already exists.", "error")

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
            INSERT INTO users (username, email, password)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash)
        )

        connection.commit()

        connection.close()

        flash("Registration successful! Please login.", "success")

        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------------------------------------------
# HOME PAGE
# ---------------------------------------------------

@app.route("/home")
def home():

    # Check whether user is logged in

    if "user_id" not in session:

        flash("Please login first.", "error")

        return redirect(url_for("login"))

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

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# ---------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------

if __name__ == "__main__":

    create_database()

    app.run(debug=True)