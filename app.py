from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import os
import base64
import random
from decouple import config

app = Flask(__name__)

# MongoDB Connection
MONGO_URI = "mongodb+srv://admin:Happyboy1234@db1.fzf97.mongodb.net/?retryWrites=true&w=majority&appName=db1"
client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

db = client.db1
users = db.users
messages = db.messages

def generate_private_key():
    return base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8')

def generate_public_key():
    return ''.join([str(random.randint(0, 9)) for _ in range(12)])

@app.route('/register', methods=['GET'])
def register():
    private_key = generate_private_key()
    public_key = generate_public_key()
    users.insert_one({"private_key": private_key, "public_key": public_key})
    return jsonify({"private_key": private_key, "public_key": public_key})

def encrypt_message(private_key, public_key, message):
    key = private_key.encode('utf-8')[:16]
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), public_key.encode('utf-8'))
    return base64.urlsafe_b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_message(private_key, public_key, encrypted_message):
    key = private_key.encode('utf-8')[:16]
    data = base64.urlsafe_b64decode(encrypted_message)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, public_key.encode('utf-8')).decode('utf-8')

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    sender_private_key = data['sender_private_key']
    receiver_public_key = data['receiver_public_key']
    message = data['message']

    receiver = users.find_one({"public_key": receiver_public_key})
    if not receiver:
        return jsonify({"error": "Receiver not found"}), 404

    encrypted_message = encrypt_message(sender_private_key, receiver_public_key, message)
    messages.insert_one({
        "receiver_public_key": receiver_public_key,
        "encrypted_message": encrypted_message
    })
    return jsonify({"status": "Message sent"})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    private_key = request.args.get('private_key')
    user = users.find_one({"private_key": private_key})
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_public_key = user['public_key']
    user_messages = messages.find({"receiver_public_key": user_public_key})

    decrypted_messages = []
    for msg in user_messages:
        decrypted_message = decrypt_message(private_key, user_public_key, msg['encrypted_message'])
        decrypted_messages.append(decrypted_message)

    return jsonify({"messages": decrypted_messages})

@app.route('/message_count', methods=['GET'])
def message_count():
    count = messages.count_documents({})
    return jsonify({"total_messages": count})

if __name__ == '__main__':
    app.run(debug=True)
