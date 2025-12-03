from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    decode_token
)
from flask_socketio import SocketIO, emit, disconnect, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    avatar_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

with app.app_context():
    db.create_all()

def allowed_file(filename):
    """Checks allowed file extensions"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        identifier = data.get('identifier')
        password = data.get('password')

        if not identifier or not password:
            return jsonify({"status": "fail", "message": "Identifier and password required"}), 400

        existing = User.query.filter_by(identifier=identifier).first()
        if existing:
            return jsonify({"status": "fail", "message": "User already exists"}), 409

        user = User(identifier=identifier)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        token = create_access_token(identity=str(user.id))

        return jsonify({
            "status": "success",
            "data": {
                "user_id": user.id,
                "identifier": user.identifier,
                "access_token": token
            }
        }), 201

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        identifier = data.get('identifier')
        password = data.get('password')

        if not identifier or not password:
            return jsonify({"status": "fail", "message": "Identifier and password required"}), 400

        user = User.query.filter_by(identifier=identifier, is_active=True).first()

        if not user or not user.check_password(password):
            return jsonify({"status": "fail", "message": "Invalid credentials"}), 401

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        return jsonify({
            "status": "success",
            "data": {
                "user_id": user.id,
                "identifier": user.identifier,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "avatar_url": user.avatar_url,
                "token_type": "bearer",
                "expires_in": int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            }
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token (OAuth 2.0 compliant)"""
    try:
        current_user_id = get_jwt_identity()

        user = User.query.get(int(current_user_id))
        if not user or not user.is_active:
            return jsonify({"status": "fail", "message": "User not found or inactive"}), 404

        new_access_token = create_access_token(identity=current_user_id)

        return jsonify({
            "status": "success",
            "data": {
                "access_token": new_access_token,
                "token_type": "bearer",
                "expires_in": int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
            }
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_user():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(int(current_user_id))

        if not user:
            return jsonify({"status": "fail", "message": "User not found"}), 404

        return jsonify({
            "status": "success",
            "data": {
                "user_id": user.id,
                "identifier": user.identifier,
                "avatar_url": user.avatar_url,
                "created_at": user.created_at.isoformat() if user.created_at else None
            }
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/user', methods=['DELETE'])
@jwt_required()
def delete_user():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(int(current_user_id))

        if not user:
            return jsonify({"status": "fail", "message": "User not found"}), 404

        if user.avatar_url:
            avatar_path = user.avatar_url.replace('/static/uploads/', '')
            full_path = os.path.join(app.config['UPLOAD_FOLDER'], avatar_path)
            if os.path.exists(full_path):
                try:
                    os.remove(full_path)
                except:
                    pass

        db.session.delete(user)
        db.session.commit()

        socketio.emit('user_deleted', {
            'user_id': user.id,
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'User account has been deleted'
        }, room=str(user.id))

        print(f"User {user.id} deleted, WebSocket room closed")

        return jsonify({
            "status": "success",
            "message": "User deleted successfully"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/avatar', methods=['POST'])
@jwt_required()
def upload_avatar():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(int(current_user_id))

        if not user:
            return jsonify({"status": "fail", "message": "User not found"}), 404

        if 'avatar' not in request.files:
            return jsonify({"status": "fail", "message": "No file part"}), 400

        file = request.files['avatar']

        if file.filename == '':
            return jsonify({"status": "fail", "message": "No selected file"}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            file.save(filepath)

            avatar_url = f"/static/uploads/{unique_filename}"

            if user.avatar_url:
                old_path = user.avatar_url.replace('/static/uploads/', '')
                old_full_path = os.path.join(app.config['UPLOAD_FOLDER'], old_path)
                if os.path.exists(old_full_path):
                    try:
                        os.remove(old_full_path)
                    except:
                        pass

            user.avatar_url = avatar_url
            db.session.commit()

            socketio.emit('avatar_changed', {
                'user_id': user.id,
                'avatar_url': avatar_url,
                'timestamp': datetime.utcnow().isoformat(),
                'message': 'Avatar has been updated'
            }, room=str(user.id))

            print(f"Avatar uploaded for user {user.id}, notification sent")

            return jsonify({
                "status": "success",
                "data": {
                    "avatar_url": avatar_url,
                    "message": "Avatar uploaded successfully"
                }
            })

        return jsonify({"status": "fail", "message": "File type not allowed"}), 400

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@socketio.on('connect')
def handle_connect():
    """Handling a WebSocket Connection"""
    try:
        token = request.args.get('token')
        if not token:
            print(f"No token provided for SID: {request.sid}")
            emit('error', {'message': 'No token provided'})
            return False

        try:
            import jwt
            decoded_token = jwt.decode(
                token,
                app.config['JWT_SECRET_KEY'],
                algorithms=['HS256'],
                options={"verify_exp": True}
            )
            user_id = decoded_token['sub']
            print(f"Token decoded, user_id: {user_id}, SID: {request.sid}")
        except jwt.ExpiredSignatureError:
            print(f"Token expired for SID: {request.sid}")
            emit('error', {'message': 'Token expired'})
            return False
        except jwt.InvalidTokenError as e:
            print(f"Invalid token for SID: {request.sid}: {e}")
            emit('error', {'message': f'Invalid token: {str(e)}'})
            return False

        user = User.query.get(int(user_id))
        if not user or not user.is_active:
            print(f"User {user_id} not found or inactive, SID: {request.sid}")
            emit('error', {'message': 'User not found or inactive'})
            return False

        join_room(str(user_id))

        print(f"WebSocket connected: User {user_id}, SID: {request.sid}")

        emit('connected', {
            'message': 'WebSocket connected successfully',
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat(),
            'sid': request.sid
        })

        return True

    except Exception as e:
        print(f"WebSocket connection error for SID {request.sid}: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        try:
            emit('error', {'message': f'Connection error: {str(e)}'})
        except:
            pass

        return False


@socketio.on('disconnect')
def handle_disconnect():
    """Handling WebSocket Disconnection"""
    print(f'Client disconnected: {request.sid}')


@socketio.on('ping')
def handle_ping(data):
    """Processing ping messages from the client"""
    emit('pong', {'data': data, 'timestamp': datetime.utcnow().isoformat()})


@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Management API</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; }
            .endpoint { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }
            h1 { color: #333; }
            code { background: #e0e0e0; padding: 2px 5px; border-radius: 3px; }
            pre { background: #f0f0f0; padding: 10px; border-radius: 5px; overflow-x: auto; }
            .websocket-demo { background: #e8f5e8; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .log { background: #2d2d2d; color: #fff; padding: 10px; border-radius: 5px; font-family: monospace; height: 200px; overflow-y: auto; }
            .success { color: #4CAF50; }
            .error { color: #f44336; }
            .info { color: #2196F3; }
        </style>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.0/socket.io.js"></script>
    </head>
    <body>
        <h1>User Management API</h1>
        <p>RESTful API for user management with WebSocket notifications</p>

        <div class="websocket-demo">
            <h2>WebSocket Live Demo</h2>
            <p>Enter your JWT token to test WebSocket notifications:</p>
            <input type="text" id="wsToken" placeholder="Paste JWT token here" style="width: 80%; padding: 10px; margin: 10px 0;">
            <br>
            <button onclick="connectWebSocket()">Connect WebSocket</button>
            <button onclick="disconnectWebSocket()" style="background-color: #ff4444; color: white;">Disconnect</button>
            <button onclick="sendPing()">Send Ping</button>

            <h3>WebSocket Log:</h3>
            <div class="log" id="wsLog">
                <div class="info">Ready to connect...</div>
            </div>
        </div>

        <div class="endpoint">
            <h3>POST /api/register</h3>
            <p>New user registration</p>
            <pre>{
  "identifier": "user@example.com",
  "password": "password123"
}</pre>
        </div>

        <div class="endpoint">
            <h3>POST /api/login</h3>
            <p>User Login</p>
            <pre>{
  "identifier": "user@example.com",
  "password": "password123"
}</pre>
        </div>

        <div class="endpoint">
            <h3>POST /api/avatar</h3>
            <p>Upload avatar (requires JWT)</p>
            <p><code>Header: Authorization: Bearer &lt;token&gt;</code></p>
            <p><code>Form-data: avatar: (image file)</code></p>
        </div>

        <div class="endpoint">
            <h3>WebSocket Connection</h3>
            <p>Connect for real-time avatar change notifications:</p>
            <p><code>ws://localhost:5000/socket.io/?token=&lt;JWT_TOKEN&gt;</code></p>
            <p>Events: <code>connected</code>, <code>avatar_changed</code>, <code>user_deleted</code>, <code>pong</code></p>
        </div>

        <p>
            <a href="/test-full" target="_blank">Full Test Page</a>
        </p>

        <script>
            let socket = null;

            function logMessage(message, type = 'info') {
                const logDiv = document.getElementById('wsLog');
                const messageDiv = document.createElement('div');
                messageDiv.className = type;
                messageDiv.textContent = '[' + new Date().toLocaleTimeString() + '] ' + message;
                logDiv.appendChild(messageDiv);
                logDiv.scrollTop = logDiv.scrollHeight;
            }

            function connectWebSocket() {
                const token = document.getElementById('wsToken').value.trim();
                if (!token) {
                    alert('Please enter a JWT token first!');
                    return;
                }

                if (socket && socket.connected) {
                    logMessage('Already connected', 'info');
                    return;
                }

                socket = io('http://localhost:5000', {
                    query: { token: token },
                    transports: ['websocket', 'polling']
                });

                socket.on('connect', () => {
                    logMessage('Connected to WebSocket server', 'success');
                });

                socket.on('connected', (data) => {
                    logMessage('Server: ' + JSON.stringify(data), 'success');
                });

                socket.on('avatar_changed', (data) => {
                    logMessage('Avatar changed: ' + JSON.stringify(data), 'success');
                });

                socket.on('user_deleted', (data) => {
                    logMessage('User deleted: ' + JSON.stringify(data), 'error');
                    socket.disconnect();
                });

                socket.on('pong', (data) => {
                    logMessage('Pong: ' + JSON.stringify(data), 'info');
                });

                socket.on('error', (data) => {
                    logMessage('Error: ' + JSON.stringify(data), 'error');
                });

                socket.on('disconnect', () => {
                    logMessage('Disconnected from server', 'info');
                });
            }

            function disconnectWebSocket() {
                if (socket) {
                    socket.disconnect();
                    logMessage('Disconnected manually', 'info');
                }
            }

            function sendPing() {
                if (socket && socket.connected) {
                    socket.emit('ping', { message: 'Hello from client!', time: Date.now() });
                    logMessage('Sent ping message', 'info');
                } else {
                    logMessage('Not connected to server', 'error');
                }
            }
        </script>
    </body>
    </html>
    '''


@app.route('/test-full')
def test_full():
    return '''
    <html>
    <head>
        <title>Full API Test</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
            button { margin: 5px; padding: 10px; }
            pre { background: #f5f5f5; padding: 10px; }
            input { margin: 5px; padding: 8px; width: 300px; }
        </style>
    </head>
    <body>
        <h1>API Testing Interface</h1>

        <div class="section">
            <h2>1. Register</h2>
            <button onclick="register()">Register Random User</button>
        </div>

        <div class="section">
            <h2>2. Login</h2>
            <input type="text" id="identifier" placeholder="identifier" value="test@test.com"><br>
            <input type="password" id="password" placeholder="password" value="password123"><br>
            <button onclick="login()">Login</button>
        </div>

        <div class="section">
            <h2>3. Get User Info</h2>
            <button onclick="getUser()">Get My Info</button>
        </div>

        <div class="section">
            <h2>4. Upload Avatar</h2>
            <input type="file" id="avatarFile"><br>
            <button onclick="uploadAvatar()">Upload Avatar</button>
        </div>

        <div class="section">
            <h2>5. Delete User</h2>
            <button onclick="deleteUser()" style="background-color: #ff4444; color: white;">Delete My Account</button>
        </div>

        <div class="section">
            <h2>Results:</h2>
            <pre id="result">Waiting for action...</pre>
        </div>

        <script>
            let token = '';

            function showResult(data) {
                document.getElementById('result').textContent = JSON.stringify(data, null, 2);
            }

            async function register() {
                const randomId = 'user' + Date.now() + '@test.com';
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        identifier: randomId,
                        password: 'password123'
                    })
                });
                const data = await response.json();
                showResult(data);
                if (data.status === 'success') {
                    token = data.data.access_token;
                    alert('Token saved!');
                }
            }

            async function login() {
                const identifier = document.getElementById('identifier').value;
                const password = document.getElementById('password').value;

                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({identifier, password})
                });
                const data = await response.json();
                showResult(data);
                if (data.status === 'success') {
                    token = data.data.access_token;
                    alert('Token saved!');
                }
            }

            async function getUser() {
                if (!token) {
                    showResult({error: 'Please login first'});
                    return;
                }

                const response = await fetch('/api/user', {
                    method: 'GET',
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                const data = await response.json();
                showResult(data);
            }

            async function uploadAvatar() {
                if (!token) {
                    showResult({error: 'Please login first'});
                    return;
                }

                const fileInput = document.getElementById('avatarFile');
                if (!fileInput.files[0]) {
                    showResult({error: 'Please select a file'});
                    return;
                }

                const formData = new FormData();
                formData.append('avatar', fileInput.files[0]);

                const response = await fetch('/api/avatar', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token
                    },
                    body: formData
                });
                const data = await response.json();
                showResult(data);
            }

            async function deleteUser() {
                if (!token) {
                    showResult({error: 'Please login first'});
                    return;
                }

                if (!confirm('Are you sure you want to delete your account? This cannot be undone!')) {
                    return;
                }

                const response = await fetch('/api/user', {
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + token
                    }
                });
                const data = await response.json();
                showResult(data);
                token = '';
                alert('Account deleted and token cleared!');
            }
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)