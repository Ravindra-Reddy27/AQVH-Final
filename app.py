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

# --- AES IMPORTS ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------- IBM Quantum Connection (Strict) ----------------

IBM_TOKEN = os.getenv("IBM_QUANTUM_TOKEN")
IBM_INSTANCE = os.getenv("IBM_QUANTUM_INSTANCE")

# Global variable to store the backend AFTER we connect
cached_backend = None

def get_ibm_backend():
    """
    Connects to IBM Quantum only when needed (Lazy Loading).
    """
    global cached_backend
    
    # If we are already connected, return the existing backend
    if cached_backend:
        return cached_backend

    print("🔌 Initiating connection to IBM Quantum...")
    try:
        service = QiskitRuntimeService(
            channel="ibm_cloud",
            token=IBM_TOKEN,
            instance=IBM_INSTANCE
        )
        # Fetch the backend
        backend = service.least_busy(operational=True, simulator=False)
        print(f"✅ Connected to: {backend.name}")
        
        cached_backend = backend
        return backend
        
    except Exception as e:
        print(f"❌ Connection Failed: {e}")
        raise e

# ---------------------------------------------------------
shared_key_bits = []
last_mode = None

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

def get_aes_key_from_bits(key_bits):
    """Converts QKD bits into a 32-byte AES key."""
    if not key_bits: return None
    key_str = "".join(map(str, key_bits))
    
    if len(key_str) == 0: return None
    
    num_bytes = (len(key_str) + 7) // 8
    key_bytes = int(key_str, 2).to_bytes(num_bytes, byteorder='big')
    
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
    
    # Cap bits to prevent excessive queue times on real hardware
    bit_num = int(data.get("bits", 5)) 
    mode = data.get("mode", "base2")
    last_mode = mode

    rng = np.random.default_rng()

    # 1. Generate Bases Classically
    alice_bases = np.round(rng.random(bit_num)).astype(int)
    alice_bits_prep = np.round(rng.random(bit_num)).astype(int) 
    bob_bases = np.round(rng.random(bit_num)).astype(int)
    eve_bases = []

    # 2. Construct the REAL Quantum Circuit
    qc = QuantumCircuit(bit_num, bit_num)

    # --- Alice's Preparation ---
    for i in range(bit_num):
        if alice_bits_prep[i] == 1:
            qc.x(i)
        if alice_bases[i] == 1:
            qc.h(i)

    # --- Eve's Interception ---
    if mode == "eve":
        eve_bases = np.round(rng.random(bit_num)).astype(int)
        for i in range(bit_num):
            # Eve chooses basis
            if eve_bases[i] == 1:
                qc.h(i)
            
            # CRITICAL FIX: Eve must MEASURE to collapse the state!
            # This mid-circuit measurement causes the QBER.
            qc.measure(i, i)
            
            # Eve rotates back (Prepare for sending)
            if eve_bases[i] == 1:
                qc.h(i) 

    qc.barrier()

    # --- Bob's Measurement ---
    for i in range(bit_num):
        if bob_bases[i] == 1:
            qc.h(i)
        
        # Bob measures (This overwrites the classical bit i with the final result)
        qc.measure(i, i)

    # 3. Submit Job to IBM Quantum
    try:
        # Connect to IBM NOW (inside the request)
        backend = get_ibm_backend()
        
        print(f"🚀 Submitting job to {backend.name}...")
        
        # Transpile for target backend
        pm = generate_preset_pass_manager(backend=backend, optimization_level=1)
        isa_qc = pm.run(qc)
        
        sampler = Sampler(mode=backend)
        
        # Run job
        job = sampler.run([isa_qc], shots=1)
        print(f"⏳ Waiting for job {job.job_id()} to complete...")
        result = job.result() 
        
        # 4. Extract Results
        pub_result = result[0]
        counts = pub_result.data.c.get_counts()
        
        measured_hex = list(counts.keys())[0]
        measured_int = int(measured_hex, 2)
        measured_bin_str = format(measured_int, f'0{bit_num}b')
        
        # Reverse bits (Little Endian -> Big Endian)
        bob_bits_measured = [int(b) for b in reversed(measured_bin_str)]
        
        # Generate Diagrams
        qc_draw_alice = qc.copy() 
        qc_draw_bob = qc.copy()
        
        bob_img_b64 = circuit_to_base64(qc_draw_bob)
        eve_img_b64 = circuit_to_base64(qc_draw_alice) if mode == "eve" else ""

        # 5. Sifting & Error Calculation
        agoodbits, bgoodbits = [], []
        match_count = 0
        total_compared_bits = 0
        error_bits_count = 0

        for n in range(bit_num):
            if alice_bases[n] == bob_bases[n]:
                total_compared_bits += 1
                agoodbits.append(int(alice_bits_prep[n]))
                bgoodbits.append(int(bob_bits_measured[n]))
                
                if int(alice_bits_prep[n]) == int(bob_bits_measured[n]):
                    match_count += 1
                else:
                    error_bits_count += 1

        fidelity = (match_count / total_compared_bits) if total_compared_bits > 0 else 1.0
        loss = 1.0 - fidelity
        qber_percent = loss * 100

        shared_key_bits = agoodbits[:]

        return jsonify({
            "mode": mode,
            "alice_bits": [int(x) for x in alice_bits_prep],
            "alice_bases": [int(x) for x in alice_bases],
            "eve_bases": [int(x) for x in eve_bases] if mode == "eve" else [],
            "bob_bases": [int(x) for x in bob_bases],
            "alice_good_bits": agoodbits,
            "bob_good_bits": bgoodbits,
            "fidelity": fidelity,
            "loss": loss,
            "qber": qber_percent,
            "total_compared": total_compared_bits,
            "error_count": error_bits_count,
            "eve_img": eve_img_b64,
            "bob_img": bob_img_b64,
            "backend_name": backend.name,
            "job_id": job.job_id()
        })

    except Exception as e:
        print(f"❌ Execution Failed: {e}")
        return jsonify({"error": str(e)}), 500

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
    app.run(host='0.0.0.0', port=8000, debug=False)