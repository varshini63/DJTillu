from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify, make_response
import hashlib
import jwt
import base64
import time
from functools import wraps

app = Flask(__name__)
app.secret_key = 'dj_tillu_is_the_best_2020_never_gonna_give_you_up'

# JWT Secret (intentionally weak for the challenge)
JWT_SECRET = 'tillu_secret_beats_2020'

# Fake users database with IDOR vulnerability
users_db = {
    1: {'username': 'tman', 'password': hashlib.md5('lillyradhika'.encode()).hexdigest(), 'role': 'dj', 'mixtape_access': False},
    2: {'username': 'fan_raju', 'password': hashlib.md5('ilovetillu'.encode()).hexdigest(), 'role': 'fan', 'mixtape_access': False},
    3: {'username': 'security_guard', 'password': hashlib.md5('clubsecurity123'.encode()).hexdigest(), 'role': 'security', 'mixtape_access': False},
    4: {'username': 'backstage_admin', 'password': hashlib.md5('b@ckst@g3_p@ss'.encode()).hexdigest(), 'role': 'admin', 'mixtape_access': False},
    999: {'username': 'doctor_lilliput', 'password': hashlib.md5('consultation_required'.encode()).hexdigest(), 'role': 'doctor', 'mixtape_access': True, 'secret_note': 'SSH_KEY: tillu_vip_access / Pass: MixtapeM@ster2020!'}
}

# SSH Credentials (for final stage)
SSH_USERS = {
    'tillu_vip_access': 'MixtapeM@ster2020!'
}

# Routes
@app.route('/')
def index():
    INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>DJ Tillu's Official Website 🎧</title>
    <style>
        /* The place where names meet secrets */
        body { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Comic Sans MS', cursive;
            color: white;
            text-align: center;
            padding: 50px;
        }
        .tillu-banner {
            font-size: 48px;
            text-shadow: 3px 3px 6px #000;
            animation: shake 0.5s infinite;
        }
        @keyframes shake {
            0% { transform: rotate(-2deg); }
            50% { transform: rotate(2deg); }
            100% { transform: rotate(-2deg); }
        }
        .mixtape-list {
            margin: 40px auto;
            max-width: 600px;
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 20px;
        }
        .background-texture {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            color: rgba(102, 126, 234, 0.01);
            font-size: 8px;
            z-index: -1;
            pointer-events: none;
        }
        a { color: #FFD700; text-decoration: none; font-size: 24px; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="tillu-banner">🎵 DJ TILLU'S CLUB 🎵</div>
    <h2>Welcome to the HOTTEST DJ in town! 🔥</h2>
    
    <div class="mixtape-list">
        <h3>Available Mixtapes:</h3>
        <p>🎶 Summer Vibes 2023 - <a href="/mixtape/1">Listen Now</a></p>
        <p>🎶 Party All Night - <a href="/mixtape/2">Listen Now</a></p>
        <p>🎶 Desi Beats - <a href="/mixtape/3">Listen Now</a></p>
    </div>
</body>
</html>
'''
    return render_template_string(INDEX_HTML)

@app.route('/robots.txt')
def robots():
    robot_content = """User-agent: *
Disallow: /admin
Disallow: /.secret_notes.txt
Disallow: /api/internal

# Hehe, robots can't dance anyway! 🤖💃
# But seriously, check out that secret_notes.txt file... oh wait, you shouldn't! 😏
"""
    response = make_response(robot_content)
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/.secret_notes.txt')
def secret_notes_fake():
    fake_flag = """
🎭 CONGRATULATIONS! YOU FOUND A SECRET! 🎭
================================================

FLAG{you_thought_this_was_easy_haha_nice_try}

Wait... this doesn't look right! 🤔
Maybe you should look more carefully at the robots.txt file?
The path seems familiar but slightly different...

Keep searching, detective! 🕵️
"""
    return fake_flag, 200, {'Content-Type': 'text/plain'}

@app.route('/secret_notes.txt')
def secret_notes():
    notes = """
DJ TILLU'S PERSONAL NOTES
=========================

🔑 JWT Secret Key: tillu_secret_beats_2020

💡 Hint: The largest three-digit number isn't just a number... it's a clearance level.

⚠️ Important: Only admin can access the unreleased mixtape. Even Tillu is not admin!

🎵 Remember: The real power lies in who you are, not who you pretend to be.
"""
    return notes, 200, {'Content-Type': 'text/plain'}

@app.route('/login', methods=['GET', 'POST'])
def login():
    LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>DJ Login Portal</title>
    <style>
        body { 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            font-family: Arial, sans-serif;
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .login-box {
            background: rgba(255,255,255,0.1);
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            min-width: 400px;
        }
        input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            border: none;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #FFD700;
            border: none;
            border-radius: 5px;
            font-size: 18px;
            cursor: pointer;
            font-weight: bold;
            color: #000;
        }
        button:hover {
            background: #FFA500;
        }
        .hint {
            font-size: 12px;
            margin-top: 20px;
            color: rgba(255,255,255,0.7);
        }
        .error {
            color: #ff6b6b;
            background: rgba(255,0,0,0.2);
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .background-texture {
            display: none !important; 
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🎧 DJ Portal Login 🎧</h2>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="hint" aria-hidden="true">
  💡 Username Hint: What Tillu calls himself when he's drugged?<div class="background-texture">NRUWY3DZOJQWI2DJNNQQ====</div>
</div>
        <p style="margin-top: 20px; text-align: center;"><a href="/" style="color: #FFD700;">← Back to Home</a></p>
    </div>
</body>
</html>
'''
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        # Check credentials
        for user_id, user_data in users_db.items():
            if user_data['username'] == username and user_data['password'] == password_hash:
                # Create JWT token (without exp for simplicity)
                token = jwt.encode({
                    'user_id': user_id,
                    'username': username,
                    'role': user_data['role']
                }, JWT_SECRET, algorithm='HS256')
                
                session['token'] = token
                session['user_id'] = user_id
                return redirect(url_for('dashboard'))
        
        return render_template_string(LOGIN_HTML, error='Invalid credentials! Try again! 🚫')
    
    return render_template_string(LOGIN_HTML, error=None)

@app.route('/dashboard')
def dashboard():
    DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>DJ Dashboard</title>
    <style>
        body { 
            background: linear-gradient(135deg, #232526 0%, #414345 100%);
            font-family: Arial, sans-serif;
            color: white;
            padding: 50px;
        }
        .profile-card {
            max-width: 600px;
            margin: 0 auto;
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
        }
        .jwt-token {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 8px;
            word-break: break-all;
            font-family: monospace;
            font-size: 12px;
            margin: 20px 0;
        }
        a { color: #FFD700; }
    </style>
</head>
<body>
    <div class="profile-card">
        <h2>Welcome, {{ username }}! 🎵</h2>
        <p><strong>User ID:</strong> {{ user_id }}</p>
        <p><strong>Role:</strong> {{ role }}</p>
        <p><strong>Mixtape Access:</strong> {{ 'YES! 🎉' if mixtape_access else 'NO 😢' }}</p>
        
        <div class="jwt-token">
            <strong>Your Session Token:</strong><br>
            {{ token }}
        </div>
        
        <p style="margin-top: 30px;">
            <a href="/profile?user_id={{ user_id }}">View Full Profile</a>
        </p>
        
        <p><a href="/logout">Logout</a></p>
    </div>
</body>
</html>
'''
    
    if 'token' not in session:
        return redirect(url_for('login'))
    
    try:
        token = session['token']
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})
        user_id = decoded['user_id']
        user = users_db.get(user_id, {})
        
        return render_template_string(DASHBOARD_HTML,
            username=decoded['username'],
            user_id=user_id,
            role=decoded['role'],
            mixtape_access=user.get('mixtape_access', False),
            token=token
        )
    except:
        return redirect(url_for('login'))

@app.route('/profile')
def profile():
    PROFILE_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body { 
            background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
            font-family: Arial, sans-serif;
            color: white;
            padding: 50px;
        }
        .profile-details {
            max-width: 700px;
            margin: 0 auto;
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
        }
        .secret-note {
            background: rgba(255,0,0,0.2);
            padding: 15px;
            border-radius: 8px;
            border: 2px solid #ff0000;
            margin-top: 20px;
        }
        a { color: #FFD700; }
    </style>
</head>
<body>
    <div class="profile-details">
        <h2>User Profile #{{ user_data.get('user_id', 'N/A') }}</h2>
        <p><strong>Username:</strong> {{ user_data.get('username', 'Unknown') }}</p>
        <p><strong>Role:</strong> {{ user_data.get('role', 'Unknown') }}</p>
        <p><strong>Mixtape Access:</strong> {{ 'Granted ✅' if user_data.get('mixtape_access', False) else 'Denied ❌' }}</p>
        
        {% if user_data.get('secret_note') %}
        <div class="secret-note">
            <h3>🔐 CONFIDENTIAL NOTE 🔐</h3>
            <p>{{ user_data.get('secret_note') }}</p>
            <p style="font-size: 12px; color: rgba(255,255,255,0.6);">
                Wait... SSH access? To what server? 🤔
            </p>
        </div>
        {% endif %}
        
        <p style="margin-top: 30px;"><a href="/dashboard">← Back to Dashboard</a></p>
    </div>
</body>
</html>
'''
    
    if 'token' not in session:
        return redirect(url_for('login'))
    
    # IDOR Vulnerability - user_id parameter not properly validated
    user_id = request.args.get('user_id', type=int)
    
    if user_id and user_id in users_db:
        user_data = users_db[user_id].copy()
        user_data['user_id'] = user_id
        
        # Add custom header hint for user #999
        response = make_response(render_template_string(PROFILE_HTML, user_data=user_data))
        if user_id == 999:
            response.headers['X-Next-Path'] = '/admin/access'
        return response
    
    return "User not found!", 404

@app.route('/admin/access', methods=['GET', 'POST'])
def admin_access():
    """Token validation endpoint - user must submit modified admin token"""
    ADMIN_ACCESS_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Access Verification</title>
    <style>
        body { 
            background: linear-gradient(135deg, #000000 0%, #434343 100%);
            font-family: 'Courier New', monospace;
            color: #00ff00;
            padding: 50px;
        }
        .admin-panel {
            max-width: 800px;
            margin: 0 auto;
            background: rgba(0,0,0,0.8);
            padding: 30px;
            border-radius: 10px;
            border: 2px solid #00ff00;
        }
        input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            border: 1px solid #00ff00;
            background: rgba(0,255,0,0.1);
            color: #00ff00;
            font-family: 'Courier New', monospace;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #00ff00;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            font-weight: bold;
            color: #000;
            margin-top: 10px;
        }
        button:hover {
            background: #00cc00;
        }
        .hint {
            background: rgba(0,255,0,0.1);
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #00ff00;
            font-size: 14px;
        }
        .result {
            background: rgba(0,0,0,0.5);
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
        }
        a { color: #FFD700; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="admin-panel">
        <h1>🔐 Admin Access Verification 🔐</h1>
        <form method="POST">
            <input type="text" name="modified_token"  required>
            <button type="submit">🚀 Submit Token</button>
        </form>
        {% if error %}
        <div class="result" style="border: 2px solid red;">
            <p style="color: red;">❌ Error: {{ error }}</p>
        </div>
        {% endif %}
        <p style="margin-top: 30px; text-align: center;">
            <a href="/dashboard">← Back to Dashboard</a>
        </p>
    </div>
</body>
</html>
'''
    
    if request.method == 'POST':
        modified_token = request.form.get('modified_token', '').strip()
        
        try:
            # Decode the submitted token (no expiry check)
            decoded = jwt.decode(modified_token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})
            
            # Check if role is admin
            if decoded.get('role') != 'admin':
                return render_template_string(ADMIN_ACCESS_HTML, 
                    error="Invalid token")
            
            # Check if it's a valid user
            if decoded.get('user_id') not in users_db:
                return render_template_string(ADMIN_ACCESS_HTML, 
                    error="Invalid user_id in token.")
            
            # Token is valid and has admin role - update session
            session.clear()
            session['token'] = modified_token
            session['user_id'] = decoded['user_id']
            
            # Redirect to success page
            return redirect(url_for('token_success'))
            
        except jwt.InvalidTokenError as e:
            return render_template_string(ADMIN_ACCESS_HTML, 
                error=f"Invalid token. Error: {str(e)}")
        except Exception as e:
            return render_template_string(ADMIN_ACCESS_HTML, 
                error=f"An error occurred: {str(e)}")
    
    return render_template_string(ADMIN_ACCESS_HTML, error=None)

@app.route('/set_token')
def set_token():
    """Automatically set the token in session"""
    token = request.args.get('token')
    if token:
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})
            session.clear()  # Clear old session
            session['token'] = token
            session['user_id'] = decoded['user_id']
            return redirect(url_for('token_success'))
        except Exception as e:
            return f"Invalid token! Error: {str(e)}", 400
    return "No token provided!", 400

@app.route('/token_success')
def token_success():
    """Success page after token update"""
    SUCCESS_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Token Updated Successfully</title>
    <style>
        body { 
            background: linear-gradient(135deg, #000000 0%, #434343 100%);
            font-family: 'Courier New', monospace;
            color: #00ff00;
            text-align: center;
            padding: 100px;
        }
        .success-box {
            background: rgba(0,0,0,0.8);
            padding: 40px;
            border-radius: 10px;
            border: 2px solid #00ff00;
            max-width: 600px;
            margin: 0 auto;
        }
        a {
            display: inline-block;
            margin-top: 30px;
            padding: 15px 30px;
            background: rgba(255,215,0,0.2);
            color: #FFD700;
            text-decoration: none;
            border-radius: 5px;
            border: 1px solid #FFD700;
            font-weight: bold;
            font-size: 16px;
        }
        a:hover {
            background: rgba(255,215,0,0.3);
        }
    </style>
</head>
<body>
    <div class="success-box">
        <h1>✅ TOKEN UPDATED SUCCESSFULLY! ✅</h1>
        <p style="margin: 30px 0; font-size: 18px;">Your role has been elevated to: <strong style="color: #FFD700;">ADMIN</strong></p>
        <p style="font-size: 14px; color: rgba(255,255,255,0.7);">
            💡 Hint: The door that never fully closes waits behind the noise.
        </p>
        <a href="/dashboard">View Dashboard</a>
    </div>
</body>
</html>
'''
    return SUCCESS_HTML

@app.route('/backdoor')
def backdoor():
    BACKDOOR_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>SSH Access Terminal</title>
    <style>
        body { 
            background: #000;
            font-family: 'Courier New', monospace;
            color: #00ff00;
            padding: 20px;
        }
        .terminal {
            max-width: 900px;
            margin: 0 auto;
            background: rgba(0,20,0,0.9);
            padding: 20px;
            border-radius: 5px;
            border: 2px solid #00ff00;
            box-shadow: 0 0 20px rgba(0,255,0,0.3);
        }
        .terminal-header {
            border-bottom: 1px solid #00ff00;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        input, button {
            background: rgba(0,255,0,0.1);
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 10px;
            font-family: 'Courier New', monospace;
            margin: 5px 0;
        }
        input {
            width: calc(100% - 22px);
        }
        button {
            cursor: pointer;
            width: 100%;
            font-size: 16px;
            font-weight: bold;
        }
        button:hover {
            background: rgba(0,255,0,0.2);
        }
        .output {
            margin-top: 20px;
            padding: 15px;
            background: rgba(0,0,0,0.5);
            border-radius: 5px;
            min-height: 100px;
        }
        .blink {
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
        .access-denied {
            color: #ff0000;
            font-weight: bold;
        }
        .access-granted {
            color: #00ff00;
            font-weight: bold;
        }
        a { color: #FFD700; }
    </style>
</head>
<body>
    <div class="terminal">
        <div class="terminal-header">
            <h2>🖥️ SECURE SSH TERMINAL v2.0 🖥️</h2>
            <p>Connecting to: djtillu-vault.ctf:2222</p>
        </div>
        
        {% if not is_admin %}
        <div class="access-denied">
            ❌ ACCESS DENIED ❌<br>
            ERROR: Invalid<br>
            <span style="font-size: 12px;">
            💡 Hint: Maybe you need to modify your JWT token?<br>
            </span>
        </div>
        {% else %}
        <form method="POST" action="/api/ssh_authenticate">
            <p>root@djtillu-vault:~$ ssh</p>
            <input type="text" name="username" placeholder="SSH Username" required>
            <input type="password" name="password" placeholder="SSH Password" required>
            <button type="submit">🔐 AUTHENTICATE</button>
        </form>
        
        <div class="output" id="output">
            <p>Waiting for authentication<span class="blink">_</span></p>
        </div>
        {% endif %}
        
        <p style="margin-top: 30px; text-align: center;">
            <a href="/dashboard">← Back to Dashboard</a>
        </p>
    </div>
</body>
</html>
'''
    
    if 'token' not in session:
        return "Access Denied! Login required! 🚫", 403
    
    try:
        token = session['token']
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})
        
        is_admin = decoded.get('role') == 'admin'
        
        return render_template_string(BACKDOOR_HTML,
            is_admin=is_admin,
            role=decoded.get('role', 'unknown')
        )
    except:
        return "Invalid token! 🚫", 403

@app.route('/api/ssh_authenticate', methods=['POST'])
def ssh_authenticate():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username in SSH_USERS and SSH_USERS[username] == password:
        flag = "w4rz0n3{dj_tillu_m1xt4p3_m4st3r_y0u_cr4ck3d_th3_b34t_2025}"
        result = f'''
<!DOCTYPE html>
<html>
<head>
    <title>FLAG CAPTURED! 🎉</title>
    <style>
        body {{ 
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            font-family: Arial, sans-serif;
            color: white;
            text-align: center;
            padding: 50px;
            animation: colorShift 3s infinite;
        }}
        @keyframes colorShift {{
            0% {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
            50% {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }}
            100% {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        }}
        .flag-box {{
            background: rgba(0,0,0,0.9);
            padding: 50px;
            border-radius: 20px;
            max-width: 700px;
            margin: 0 auto;
            border: 5px solid #FFD700;
            animation: glow 1.5s ease-in-out infinite alternate;
        }}
        @keyframes glow {{
            from {{ 
                box-shadow: 0 0 20px #FFD700, 0 0 30px #FFD700;
            }}
            to {{ 
                box-shadow: 0 0 40px #FFD700, 0 0 60px #FFD700;
            }}
        }}
        .flag {{ 
            font-size: 28px;
            font-family: 'Courier New', monospace;
            color: #00ff00;
            padding: 25px;
            background: rgba(0,255,0,0.15);
            border-radius: 10px;
            margin: 25px 0;
            letter-spacing: 2px;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); }}
            50% {{ transform: scale(1.05); }}
        }}
        .trophy {{
            font-size: 80px;
            animation: bounce 1s infinite;
        }}
        @keyframes bounce {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-20px); }}
        }}
    </style>
</head>
<body>
    <div class="flag-box">
        <div class="trophy">🏆</div>
        <h1>🎉 CONGRATULATIONS! 🎉</h1>
        <h2>You've Successfully Hacked DJ Tillu's Vault!</h2>
        <div class="flag">{flag}</div>
        <h3>🎵 UNRELEASED SUPER HIT MIXTAPE UNLOCKED! 🎵</h3>
        <p style="font-size: 20px; margin: 30px 0;">
            DJ Tillu says:<br>
            <em>"Arre bhaiyya! You are the real hacker! 🎧<br>
            This mixtape is fire! 🔥 Enjoy the beats!"</em>
        </p>

        <p style="margin-top: 40px;">
            <a href="/" style="color: #FFD700; font-size: 20px; text-decoration: none;">← Back to Home</a>
        </p>
    </div>
</body>
</html>
'''
        return result
    
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Failed</title>
    <style>
        body {
            background: #000;
            color: #ff0000;
            font-family: 'Courier New', monospace;
            text-align: center;
            padding: 100px;
        }
        .error-box {
            background: rgba(255,0,0,0.1);
            border: 2px solid #ff0000;
            padding: 40px;
            border-radius: 10px;
            max-width: 500px;
            margin: 0 auto;
        }
        a { color: #FFD700; }
    </style>
</head>
<body>
    <div class="error-box">
        <h1>❌ SSH AUTHENTICATION FAILED ❌</h1>
        <p>Invalid credentials!</p>
        <p style="margin-top: 30px;">
            <a href="/backdoor">← Try Again</a>
        </p>
    </div>
</body>
</html>
''', 403

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/mixtape/<int:mixtape_id>')
def mixtape(mixtape_id):
    return f"<h1>🎵 Mixtape #{mixtape_id} 🎵</h1><p>This mixtape is playing... 🎶</p><p><a href='/' style='color: #FFD700;'>← Back</a></p>"

if __name__ == '__main__':
    print("=" * 60)
    print("🎧 DJ TILLU'S CTF CHALLENGE SERVER STARTING... 🎧")
    print("=" * 60)
    print("\n✅ Server running at: http://localhost:5000")
    print("✅ Challenge starts at: http://localhost:5000")
    print("\n🎯 Good luck, hacker! Find the unreleased mixtape!")
    print("\n" + "=" * 60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
