from ens import ENS
from web3 import Web3

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import Flask
from flask import request, jsonify
from flask_cors import CORS, cross_origin


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

w3 = Web3(Web3.WebsocketProvider("wss://mainnet.infura.io/ws"))
ns = ENS.fromWeb3(w3)

@app.route("/resolve", methods=["POST"])
@cross_origin()
def resolve_ens():
    data = request.json
    ens_name = data["name"]
    pubkey = data["pubkey"]

    addr = ns.address(ens_name)

    public_key_pem_loaded = load_pem_public_key(pubkey.encode(), backend=default_backend())

    encrypted_addr = encrypt(public_key_pem_loaded, addr)
    return jsonify({"encryptedAddress": encrypted_addr, "address": addr, "name": ens_name})



def encrypt(pubkey, message):
    encrypted_message = pubkey.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
                label=None
            )
        )

    return str(base64.b64encode(encrypted_message), 'utf-8')
