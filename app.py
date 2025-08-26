from flask import Flask, render_template, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Change this in production, but for challenge it's fine.

# Static user data (participants use username: 'user', password: 'password')
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
        # Predictable CSRF token: Plaintext username (vulnerability - easy to predict)
        csrf_token = session['username']
        return render_template('change_password.html', csrf_token=csrf_token)
    
    # POST handling
    # Weak Referer check: Reject only if Referer is present and incorrect (allows blank/absent Referer)
    referer = request.headers.get('Referer', '')
    host = request.host_url[:-1]  # Remove trailing slash
    if referer and not referer.startswith(host):
        return 'Invalid Referer'
    
    # Check CSRF token
    csrf_token = request.form.get('csrf_token')
    expected_csrf = session['username']
    if csrf_token != expected_csrf:
        return 'Invalid CSRF token'
    
    new_pass = request.form.get('new_password')
    confirm = request.form.get('confirm_password')
    if new_pass != confirm:
        return render_template('change_password.html', csrf_token=expected_csrf, error='Passwords do not match')
    
    # Change password (no old password required - additional bad design for exploitability)
    users[session['username']]['password'] = new_pass
    
    # Reveal flag only if Referer is blank (indicating likely CSRF exploitation)
    if not referer:
        return 'Password changed successfully. FLAG: flag{csrf_exploited_with_predictable_plaintext_token_and_blank_referer} <a href="/dashboard">Back to Dashboard</a>'
    else:
        return 'Password changed successfully. <a href="/dashboard">Back to Dashboard</a>'

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/reset_password')
def reset_password():
    # Reset password to default for shared user (to allow multiple participants)
    users['user']['password'] = 'password'
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
