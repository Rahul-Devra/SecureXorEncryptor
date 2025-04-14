# 🔐 SecureXorEncryptor

A simple Java utility to encrypt and decrypt text files using XOR encryption and password-based authentication.

---

## 🚀 Usage Guide

### Step-by-Step Console Flow (Windows)

> ⚠️ Make sure you're in the `Assignment` directory and have `test.txt` and `key.txt` already created.


# 1. Move to the project directory
cd C:\Users\RAHUL DEVRA\Downloads\Assignment

# 2. Compile the Java program
javac src/SecureXorEncryptor.java -d .

# 3. Encrypt the test.txt file
java SecureXorEncryptor -e test.txt encrypted.txt key.txt

🖥️ Expected output for encryption:
Authentication required for encryption
Enter authentication password: ****
Confirm password: ****
Enter encryption/decryption password: ****
Encryption completed successfully.

# 4. Decrypt the encrypted.txt file
java SecureXorEncryptor -d encrypted.txt decrypted.txt key.txt

🖥️ Expected output for decryption:
Authentication required for decryption
Enter authentication password: ****
Confirm password: ****
Enter encryption/decryption password: ****
Decryption completed successfully.
✅ You can now open decrypted.txt to verify it matches your original message from test.txt.
