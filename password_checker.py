import requests
import hashlib
import re

def chech_password_strength(password):
    #basic stregth criteria
    if len(password) < 8:
        return "Weak: Way too short! (at least have up to 8 chars)"
    if not re.search(r"[A-Z]", password):
        return "Weak: You've got to add uppercase letters"
    if not re.search(r"[0-9]", password):
        return "Weak: No numbers"
    if not re.search(r"[!@#$%^&*]", password):
        return "Weak: No special characters"
    return "Strong!"

def check_breach(password):
    #hash the password with SHA-1
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[:5]

    #query HIBP API (k-anonymity for privacy)
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    hashes = response.text.splitlines()

    #check if hash suffix exists
    for h in hashes:
        if suffix in h:
            count = int(h.split(":")[1])
            return f"Breached: Found in {count} breaches"
    return "Not found in breaches"

#main exception
password = input("Enter a password to check: ")
strength = chech_password_strength(password)
breach_status = check_breach(password)
print(f"Strength: {strength}")
print(f"Breach Status: {breach_status}")