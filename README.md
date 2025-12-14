# AES-256 File Encryption & Decryption Tool

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Cryptography](https://img.shields.io/badge/Security-AES--256-green)

## 📌 Overview
This project is a Python-based AES-256 encryption and decryption tool designed to secure files of any type, including text documents, images, and binary data. It demonstrates a hands-on implementation of symmetric cryptography, key management, and secure file handling practices.

The tool is intended for educational and academic purposes, helping learners understand cryptographic principles and file security concepts.

---

## 🚀 Features
* **AES-256 Symmetric Encryption:** Uses a 256-bit key for military-grade security.
* **Universal File Support:** Encrypts and decrypts multiple file types (txt, jpg, png, pdf, etc.).
* **Secure Randomization:** Generates a unique IV (Initialization Vector) for every encryption operation.
* **Data Integrity:** Implements PKCS7 padding for proper block alignment.
* **Educational Codebase:** Clear, documented Python code designed for learning.

---

## 🛠️ Technologies Used
* **Language:** Python 3.x
* **Library:** `cryptography` (Fernet/Primitives)
* **Standard Modules:** `os`, `base64`

---

## 🔐 Cryptography Design Choices

### 1. AES-256 Key
This project uses **AES (Advanced Encryption Standard)** with a **256-bit (32-byte) symmetric key**. This offers strong resistance against brute-force attacks while remaining efficient for file processing.

### 2. Mode of Operation: CBC (Cipher Block Chaining)
*Note: This project utilizes CBC mode.*
* **Mechanism:** Each plaintext block is XORed with the previous ciphertext block before encryption. This prevents pattern leakage (i.e., identical plaintext blocks do not result in identical ciphertext blocks).
* **Security:** Provides high confidentiality.

### 3. IV (Initialization Vector) Generation
For each encryption operation, a new, random IV is generated using a cryptographically secure random number generator (`os.urandom`).
* **Purpose:** This ensures that encrypting the same file twice with the same key results in completely different ciphertext, preventing frequency analysis attacks.

### 4. Padding (PKCS7)
AES is a block cipher that operates on fixed-size blocks (16 bytes). Because files rarely match this size perfectly, padding is required.
* **Implementation:** We use **PKCS7 padding** to add bytes to the end of the plaintext before encryption.
* **Decryption:** The padding is validated and removed safely during decryption to restore the original file content.

---

## 💻 Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/aes-256-file-encryption.git](https://github.com/YOUR_USERNAME/aes-256-file-encryption.git)
   cd aes-256-file-encryption
