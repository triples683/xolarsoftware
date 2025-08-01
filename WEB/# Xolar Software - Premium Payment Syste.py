# Xolar Software - Premium Payment System with Login, Cookies, DB, MTN & Airtel

from flask import Flask, request, render_template, redirect, session, make_response
import sqlite3
import bcrypt
import uuid

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production
DATABASE = 'xolar.db'

# --- Helper Functions ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_premium BOOLEAN DEFAULT FALSE
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount DECIMAL(10, 2),
            method TEXT,
            status TEXT,
            reference TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')


# --- Routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())

        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
                return redirect('/login')
        except sqlite3.IntegrityError:
            return "Email already exists."
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode()

        with sqlite3.connect(DATABASE) as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user and bcrypt.checkpw(password, user[2]):
                session['user_id'] = user[0]
                resp = make_response(redirect('/dashboard'))
                resp.set_cookie('session_token', str(uuid.uuid4()), max_age=3600)
                return resp
        return "Invalid credentials."
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    with sqlite3.connect(DATABASE) as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        return render_template('dashboard.html', user=user)

@app.route('/pay', methods=['POST'])
def pay():
    if 'user_id' not in session:
        return redirect('/login')

    method = request.form['method']  # 'mtn' or 'airtel'
    amount = 10000  # UGX fixed price
    reference = str(uuid.uuid4())

    # Simulate payment logic (in real case, integrate with API or Flutterwave)
    payment_status = "successful"

    with sqlite3.connect(DATABASE) as conn:
        conn.execute("INSERT INTO payments (user_id, amount, method, status, reference) VALUES (?, ?, ?, ?, ?)",
                     (session['user_id'], amount, method, payment_status, reference))
        if payment_status == "successful":
            conn.execute("UPDATE users SET is_premium=1 WHERE id=?", (session['user_id'],))

    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect('/'))
    resp.set_cookie('session_token', '', max_age=0)
    return resp


# --- Initialize DB ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
