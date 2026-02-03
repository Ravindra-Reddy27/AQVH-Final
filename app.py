
import os
import base64
import io
import numpy as np
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv

from qiskit import QuantumCircuit
from qiskit.visualization import circuit_drawer
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
import matplotlib
matplotlib.use("Agg")  # Non-GUI backend for Flask
import matplotlib.pyplot as plt

# --- AES IMPORTS (NEW) ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------- IBM Quantum Connection ----------------

service = QiskitRuntimeService(
    channel="ibm_cloud",
    token=os.getenv("IBM_QUANTUM_TOKEN"),
    instance=os.getenv("IBM_QUANTUM_INSTANCE")
)

# backend = service.backend("ibm_brisbane")
backend = service.least_busy(operational=True, simulator=False)
print("✅ Connected to IBM Quantum backend:", backend.name)

# ---------------------------------------------------------
shared_key_bits = []
last_mode = None  # "base2" or "eve"

# ---------- Helpers ----------

def circuit_to_base64(qc):
    try:
        fig = circuit_drawer(qc, output="mpl")
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode("utf-8")
    except Exception:
        return ""

# (NEW) AES Key Helper
def get_aes_key_from_bits(key_bits):
    """Converts QKD bits into a 32-byte AES key."""
    if not key_bits: return None
    key_str = "".join(map(str, key_bits))
    num_bytes = (len(key_str) + 7) // 8
    key_bytes = int(key_str, 2).to_bytes(num_bytes, byteorder='big')
    # Pad to 32 bytes (256-bit key) or truncate
    if len(key_bytes) < 32:
        return key_bytes.ljust(32, b'\0')
    return key_bytes[:32]

# ---------- Routes ----------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/explanation")
def explanation():
    return render_template("explanationaeschange.html")


@app.route("/run", methods=["POST"])
def run_qkd():
    global shared_key_bits, last_mode
    data = request.get_json() or {}
    bit_num = int(data.get("bits", 4))
    mode = data.get("mode", "base2")
    last_mode = mode

    rng = np.random.default_rng()

    # Alice
    abits = np.round(rng.random(bit_num))
    abase = np.round(rng.random(bit_num))

    # Alice’s circuit
    qc_alice = QuantumCircuit(bit_num, bit_num)
    for n in range(bit_num):
        if abits[n] == 0 and abase[n] == 1:
            qc_alice.h(n)
        if abits[n] == 1:
            qc_alice.x(n)
            if abase[n] == 1:
                qc_alice.h(n)

    # Eve (intercept + resend)
    ebase, ebits = [], []
    eve_img_b64 = ""

    if mode == "eve":
        ebase = np.round(rng.random(bit_num))
        qc_eve = qc_alice.copy()
        for m in range(bit_num):
            if ebase[m] == 1:
                qc_eve.h(m)
            qc_eve.measure(m, m)

        # Simulate Eve’s measurement
        try:
            pm = generate_preset_pass_manager(target=backend.target, optimization_level=1)
            qc_isa = pm.run(qc_eve)
            sampler = Sampler(backend)
            job = sampler.run([qc_isa], shots=1)
            result = job.result()
            counts = result[0].data.c.get_counts()
            key_str = list(counts.keys())[0]
            ebits = [int(b) for b in key_str[::-1]]
        except Exception as e:
            print("⚠️ Eve run failed, randomizing:", e)
            ebits = np.round(rng.random(bit_num)).astype(int).tolist()

        eve_img_b64 = circuit_to_base64(qc_eve)

        # Eve resends qubits
        qc_alice = QuantumCircuit(bit_num, bit_num)
        for n in range(bit_num):
            if ebits[n] == 0 and ebase[n] == 1:
                qc_alice.h(n)
            if ebits[n] == 1:
                qc_alice.x(n)
                if ebase[n] == 1:
                    qc_alice.h(n)

    # Bob’s circuit
    bbase = np.round(rng.random(bit_num))
    qc_bob = qc_alice.copy()
    for m in range(bit_num):
        if bbase[m] == 1:
            qc_bob.h(m)
        qc_bob.measure(m, m)

    bob_img_b64 = circuit_to_base64(qc_bob)

    # Run Bob’s circuit
    try:
        pm = generate_preset_pass_manager(target=backend.target, optimization_level=1)
        qc_isa = pm.run(qc_bob)
        sampler = Sampler(backend)
        job = sampler.run([qc_isa], shots=1024)
        result = job.result()
        counts = result[0].data.c.get_counts()
        key_str = max(counts, key=counts.get)
        bbits = [int(b) for b in key_str[::-1]]
    except Exception as e:
        print("⚠️ Quantum run failed, fallback:", e)
        bbits = np.round(rng.random(bit_num)).astype(int).tolist()

    # Compare bases
    agoodbits, bgoodbits, match_count = [], [], 0
    for n in range(bit_num):
        if abase[n] == bbase[n]:
            agoodbits.append(int(abits[n]))
            bgoodbits.append(bbits[n])
            if int(abits[n]) == bbits[n]:
                match_count += 1

    fidelity = (match_count / len(agoodbits)) if agoodbits else 0.0
    loss = 1.0 - fidelity if agoodbits else 1.0

    shared_key_bits = agoodbits[:]

    return jsonify({
        "mode": mode,
        "alice_bits": [int(x) for x in abits.tolist()],
        "alice_bases": [int(x) for x in abase.tolist()],
        "eve_bases": [int(x) for x in ebase.tolist()] if mode == "eve" else [],
        "bob_bases": [int(x) for x in bbase.tolist()],
        "alice_good_bits": agoodbits,
        "bob_good_bits": bgoodbits,
        "fidelity": fidelity,
        "loss": loss,
        "eve_img": eve_img_b64,
        "bob_img": bob_img_b64
    })

# (NEW) AES Encrypt Route
@app.route("/encrypt", methods=["POST"])
def encrypt():
    if not shared_key_bits or last_mode == "eve":
        return jsonify({"error": "Encryption not allowed (no secure key)."}), 400
    
    data = request.get_json() or {}
    text = data.get("message", "")
    if not text: return jsonify({"error": "Message cannot be empty."}), 400

    try:
        key = get_aes_key_from_bits(shared_key_bits)
        iv = os.urandom(16)
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        encrypted_msg = base64.b64encode(iv + ciphertext).decode('utf-8')
        return jsonify({"ciphertext": encrypted_msg})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# (NEW) AES Decrypt Route
@app.route("/decrypt", methods=["POST"])
def decrypt():
    if not shared_key_bits or last_mode == "eve":
        return jsonify({"error": "Decryption not allowed."}), 400
        
    data = request.get_json() or {}
    encrypted_msg_b64 = data.get("ciphertext", "")
    if not encrypted_msg_b64: return jsonify({"error": "Ciphertext required."}), 400

    try:
        key = get_aes_key_from_bits(shared_key_bits)
        encrypted_data = base64.b64decode(encrypted_msg_b64)
        
        iv = encrypted_data[:16]
        actual_ciphertext = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return jsonify({"original": plaintext.decode('utf-8')})
    except Exception as e:
        return jsonify({"error": "Decryption failed."}), 400

if __name__ == "__main__":
    app.run(debug=True)