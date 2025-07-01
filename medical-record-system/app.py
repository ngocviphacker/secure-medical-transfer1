# app.py
from flask import Flask, render_template, request, redirect, flash
from flask_socketio import SocketIO, emit
import os, json, base64
from werkzeug.utils import secure_filename
from flask import send_from_directory
from crypto_utils import *

app = Flask(__name__)
app.secret_key = 'secret'
socketio = SocketIO(app)

UPLOAD_FOLDER = 'uploads'
RECEIVED_FOLDER = 'received'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RECEIVED_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return redirect('/send')

@app.route('/send')
def send_page():
    return render_template('send.html')

@app.route('/receive')
def receive_page():
    return render_template('receive.html')

@app.route('/chat')
def chat_page():
    return render_template('chat.html')

# GỬI FILE
@app.route('/send', methods=['POST'])
def send_file():
    file = request.files['file']
    password = request.form['password']
    patient_id = request.form['patient_id']
    filename = secure_filename(file.filename)
    data = file.read()

    sender_private = load_key('keys/sender_private.pem', True)
    receiver_public = load_key('keys/receiver_public.pem', False)
    session_key = os.urandom(32)
    iv, cipher = aes_encrypt(data, session_key)

    metadata = create_metadata(filename, patient_id)
    signature = sign_metadata(sender_private, metadata)
    encrypted_key = encrypt_session_key(receiver_public, session_key)

    packet = {
        "filename": filename,
        "metadata": metadata,
        "iv": base64.b64encode(iv).decode(),
        "cipher": base64.b64encode(cipher).decode(),
        "hash": hash_integrity(iv, cipher),
        "sig": base64.b64encode(signature).decode(),
        "pwd": hash_password(password),
        "enc_session_key": base64.b64encode(encrypted_key).decode()
    }

    socketio.emit('incoming_packet', packet)
    flash("✅ Gói tin đã được gửi đến người nhận.")
    return redirect('/send')

# NHẬN FILE TỰ ĐỘNG QUA SOCKETIO
@app.route('/receive_auto', methods=['POST'])
def receive_auto():
    content = request.get_json()
    receiver_pwd = content.get('receiver_password', '')

    try:
        iv = base64.b64decode(content['iv'])
        cipher = base64.b64decode(content['cipher'])
        signature = base64.b64decode(content['sig'])
        enc_session_key = base64.b64decode(content['enc_session_key'])

        receiver_private = load_key('keys/receiver_private.pem', True)
        sender_public = load_key('keys/sender_public.pem', False)

        # Toàn vẹn
        if hash_integrity(iv, cipher) != content['hash']:
            socketio.emit('message', '❌ Sai hash')
            return "❌ Sai hash", 400

        # Mật khẩu
        if hash_password(receiver_pwd) != content['pwd']:
            socketio.emit('message', '❌ Sai mật khẩu')
            return "❌ Sai mật khẩu", 400

        # Chữ ký
        if not verify_signature(sender_public, content['metadata'], signature):
            socketio.emit('message', '❌ Chữ ký không hợp lệ')
            return "❌ Chữ ký không hợp lệ", 400

        # Giải mã
        session_key = decrypt_session_key(receiver_private, enc_session_key)
        plaintext = aes_decrypt(iv, cipher, session_key)

        output_path = os.path.join(RECEIVED_FOLDER, content['filename'])
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        socketio.emit('message', '✅ File đã giải mã & lưu thành công')
        return "✅ File đã được lưu thành công", 200

    except Exception as e:
        return f"❌ Lỗi: {str(e)}", 500

# CHAT
@socketio.on('message')
def handle_message(msg):
    print("[Chat]", msg)
    emit('message', msg, broadcast=True)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(RECEIVED_FOLDER, filename, as_attachment=True)

# CHẠY
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
