from flask import Flask, render_template, request, redirect, session
import hashlib
import pyotp
import time
from datetime import datetime
import math


def send_verification_code(email, phone_number, code):
    print(f"Verification code: {code}")
    print(f"Sent to email: {email}")
    print(f"Sent to phone number: {phone_number}")


app = Flask(__name__)
app.secret_key = "my_secret_key"
users = {
    "somaiya": {                                                 #username
        "password_hash": hashlib.sha256(b"python").hexdigest(),  #password
        "email": "somaiya@example.com",
        "phone_number": "9867549332",
        "secret_key": pyotp.random_base32() #creates random OTPs which expire after maximum of 60 seconds Validity 60 sec
    }    
}


# Defining the login route
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username not in users:
            error = "User not found"
            return render_template("login.html", error=error)

        password_hash = users[username]["password_hash"]
        if password_hash != hashlib.sha256(password.encode()).hexdigest():
            error = "Incorrect password"
            return render_template("login.html", error=error)

        session["username"] = username

        return redirect("/verify")

    return render_template("login.html")


# Defining the 2-factor authentication route
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "username" not in session:
        return redirect("/")

    username = session["username"]
    secret_key = users[username]["secret_key"]

    totp = pyotp.TOTP(secret_key)
    verification_code = totp.now()

    email = users[username]["email"]
    phone_number = users[username]["phone_number"]
    send_verification_code(email, phone_number, verification_code)

    if request.method == "POST":
        user_code = request.form["code"]

        if totp.verify(user_code):
            return redirect("/home")
        else:
            error = "Incorrect verification code"
            return render_template("verify.html", error=error, totp=totp, time=time, int=int)

    if 'remaining_time' not in session:
        session['remaining_time'] = 60 - int(time.time() % 60)
    else:
        session['remaining_time'] -= int(time.time() % 60)
        if session['remaining_time'] <= 0:
            session['remaining_time'] = 60
    remaining_time = session['remaining_time']

    return render_template('verify.html', totp=totp, remaining_time=remaining_time)


@app.route("/home")
def home():
    if "username" not in session:
        return redirect("/")

    username = session["username"]
    email = users[username]["email"]
    phone_number = users[username]["phone_number"]

    return render_template("home.html", username=username, email=email, phone_number=phone_number)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)