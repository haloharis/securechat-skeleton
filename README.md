# SecureChat – Assignment #2

This project implements a **console-based Secure Chat System** using **custom application-layer security**, demonstrating:

✅ **Confidentiality**
✅ **Integrity**
✅ **Authentication**
✅ **Non-Repudiation**
(Collectively: **CIANR**)

The system uses a custom protocol with **AES encryption, RSA signatures, DH key exchange, X.509 certificates, salted password hashing, transcript hashing**, and replay protection.

---

# 📁 Project Structure

```
securechat/
├── app/
│   ├── client.py          # Client workflow
│   ├── server.py          # Server workflow
│   ├── crypto/
│   │   ├── aes.py         # AES-128 ECB + PKCS#7
│   │   ├── dh.py          # Diffie–Hellman helpers
│   │   ├── pki.py         # X.509 certificate validation
│   │   └── sign.py        # RSA SHA-256 sign/verify
│   ├── common/
│   │   ├── protocol.py    # Message formats (Hello, Login, Msg, Receipt)
│   │   └── utils.py       # Base64, timestamps, sha256
│   └── storage/
│       ├── db.py          # MySQL user store (salt + SHA256)
│       └── transcript.py  # Append-only transcript + transcript hash
├── scripts/
│   ├── gen_ca.py          # Generate Root CA
│   └── gen_cert.py        # Issue client/server certificates
├── certs/                 # Certificates (gitignored)
├── transcripts/           # Chat transcripts (gitignored)
├── .env.example
├── requirements.txt
└── README.md
```

---

# ⚙️ **Setup & Execution Guide**

## **1. Clone or fork your repo**

(Replace with your actual link)

```
git clone https://github.com/<yourusername>/securechat.git
cd securechat
```

---

## **2. Create virtual environment**

Windows:

```
python -m venv .venv
.venv\Scripts\activate
```

Linux/Mac:

```
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

Copy environment file:

```
copy .env.example .env   (Windows)
cp .env.example .env     (Linux/Mac)
```

---

# 🗄️ **3. MySQL Setup (Docker)**

Run MySQL in Docker (change port if 3306 is busy):

```
docker run -d --name securechat-db ^
  -e MYSQL_ROOT_PASSWORD=rootpass ^
  -e MYSQL_DATABASE=securechat ^
  -e MYSQL_USER=scuser ^
  -e MYSQL_PASSWORD=scpass ^
  -p 3307:3306 mysql:8
```

Initialize tables:

```
python -m app.storage.db --init
```

---

# 🔐 **4. Certificate Generation**

### **Step A — Generate Root CA**

```
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

### **Step B — Generate Server Certificate**

```
python scripts/gen_cert.py --cn server.local --out certs/server
```

### **Step C — Generate Client Certificate**

```
python scripts/gen_cert.py --cn client.local --out certs/client
```

---

# 🚀 **5. Running SecureChat**

### Start Server:

```
python -m app.server
```

### Start Client (new terminal):

```
python -m app.client
```

---

# 💬 **Sample Interaction**

### **Client Input →**

```
hello
login haris password123
msg hello sir
logout
```

### **Server Output →**

```
HELLO_OK
LOGIN_OK
MSG_OK seq=4
LOGOUT_OK
```

All messages after login are **AES encrypted + RSA signed + sequence numbered**.

---

# 🔒 **Security Features Implemented**

### 🔹 **Confidentiality**

AES-128 (ECB) encryption using key derived from Diffie–Hellman shared secret.

### 🔹 **Integrity & Authentication**

Each message contains:

* sha256 digest
* RSA signature (PKCS#1 v1.5)

### 🔹 **Non-Repudiation**

A **SessionReceipt** is generated:

* transcript hash
* server signature
  This allows **offline verification**.

### 🔹 **Replay Protection**

Sequence numbers:

* if `seq < expected` → **REPLAY**
* if tampered digest/signature → **SIG_FAIL**

### 🔹 **Certificate Validation**

* CA signature
* expiration check
* hostname (CN)
* chain of trust

---

# 🧪 **Testing & Evidence (Required in Report)**

### ✔ **1. Wireshark — Encrypted Payload Only**

Apply filters:

```
tcp.port == 5000
```

Expected:

* no plaintext user messages
* only encrypted AES data visible

---

### ✔ **2. Invalid Certificate Test**

Use:

* expired cert
* self-signed cert
* mismatched CN

Expected client output:

```
BAD_CERT
```

---

### ✔ **3. Tamper Test**

Flip 1 byte in ciphertext file:

```
SIG_FAIL
```

---

### ✔ **4. Replay Test**

Resend old ciphertext:

```
REPLAY
```

---

### ✔ **5. Non-Repudiation Verification**

Offline Python script must verify:

1. each message digest
2. each message RSA signature
3. verify SessionReceipt signature over TranscriptHash
4. any edit must fail verification

---

# 🧵 **Environment Variables (.env)**

```
DB_HOST=localhost
DB_PORT=3307
DB_USER=scuser
DB_PASSWORD=scpass
DB_NAME=securechat

SERVER_HOST=127.0.0.1
SERVER_PORT=5000
```

---

# 🔗 GitHub Repository Link

👉 **[https://github.com/haloharis/securechat-skeleton](https://github.com/haloharis/securechat-skeleton)**


---

If you want, I can also prepare your **Report.docx** or **TestReport.docx**.
