from flask import Flask, render_template, request, session, redirect, url_for
import hashlib
import time

app = Flask(__name__)
app.secret_key = 'super_secret_key'


users = {
    'user': {
        'password': 'password',
        'balance': 1000,
        'account_number': '1234-5678-9012',
        'recent_transactions': [
            {'date': '2025-08-20', 'description': 'Deposit', 'amount': '+500.00'},
            {'date': '2025-08-22', 'description': 'Withdrawal', 'amount': '-200.00'},
            {'date': '2025-08-25', 'description': 'Transfer', 'amount': '-100.00'}
        ]
    }
}

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username in users and users[username]['password'] == password:
        session['username'] = username
        return redirect(url_for('dashboard'))
    return render_template('login.html', error='Invalid credentials')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    user_data = users[session['username']]
    return render_template('dashboard.html', username=session['username'], balance=user_data['balance'],
                           account_number=user_data['account_number'], transactions=user_data['recent_transactions'])

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'GET':
     
        csrf_token = hashlib.md5((session['username'] + str(int(time.time()))).encode()).hexdigest()
        session['csrf_token'] = csrf_token 
        return render_template('change_password.html', csrf_token=csrf_token)
    

    referer = request.headers.get('Referer', '')
    host = request.host_url[:-1]
    if referer and not referer.startswith(host):
        return 'Invalid Referer'

    
    csrf_token = request.form.get('csrf_token')
    expected_csrf = session.get('csrf_token')
    if csrf_token != expected_csrf:
        return 'Invalid CSRF token'
    
    new_pass = request.form.get('new_password')
    confirm = request.form.get('confirm_password')
    if new_pass != confirm:
        return render_template('change_password.html', csrf_token=expected_csrf, error='Passwords do not match')
    
   
    session['password_changed'] = True 
    

    if not referer:
        return 'Password change simulated successfully. FLAG: flag{csrf_exploited_with_dynamic_md5_token_and_blank_referer} <a href="/dashboard">Back to Dashboard</a>'
    return 'Password change simulated successfully. <a href="/dashboard">Back to Dashboard</a>'

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('csrf_token', None)
    session.pop('password_changed', None) 
    return redirect(url_for('index'))

@app.route('/reset_password')
def reset_password():
    session.pop('password_changed', None) 
    return redirect(url_for('index'))

@app.route('/submit_poc', methods=['GET', 'POST'])
def submit_poc():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'GET':
        return render_template('submit_poc.html')
    

    poc_html = request.form.get('poc_html')
    if not poc_html:
        return render_template('submit_poc.html', error='Please provide a POC HTML.')
    

    current_token = hashlib.md5((session['username'] + str(int(time.time()))).encode()).hexdigest()
    

    if 'user' in poc_html and current_token in poc_html and 'no-referrer' in poc_html.lower():
        session['password_changed'] = True
        return 'POC submitted successfully. FLAG: flag{csrf_exploited_with_dynamic_md5_token_and_blank_referer} <a href="/dashboard">Back to Dashboard</a>'
    else:
        return render_template('submit_poc.html', error='Invalid POC. Ensure it includes the username "user", the correct dynamic CSRF token, and "no-referrer" policy.')
