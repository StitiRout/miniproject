import re

# List of common weak passwords
COMMON_PASSWORDS = ["123456", "password", "qwerty", "letmein", "111111", "12345678"]

def analyze_password(password):
    score = 0
    tips = []

    # Length check
    if len(password) < 8:
        tips.append("Make your password at least 8 characters long.")
    elif len(password) >= 12:
        score += 2
    else:
        score += 1

    # Check for lowercase, uppercase, digits, special chars
    if re.search(r'[a-z]', password):
        score += 1
    else:
        tips.append("Add lowercase letters.")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        tips.append("Add uppercase letters.")
    
    if re.search(r'[0-9]', password):
        score += 1
    else:
        tips.append("Include numbers.")

    if re.search(r'[@$!%*?&]', password):
        score += 1
    else:
        tips.append("Use special characters like @, $, %, etc.")

    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        tips.append("Avoid repeated characters.")
    
    # Check for common passwords
    if password.lower() in COMMON_PASSWORDS:
        tips.append("Avoid using common passwords.")

    # Strength rating
    if score >= 6:
        strength = "Strong "
    elif score >= 4:
        strength = "Moderate "
    else:
        strength = "Weak "

    return strength, tips


# --- Main Program ---
if __name__ == "__main__":
    user_pass = input("Enter a password to analyze: ")
    strength, advice = analyze_password(user_pass)
    
    print("\nPassword Strength:", strength)
    if advice:
        print("Suggestions to improve:")
        for tip in advice:
            print("-", tip)
    else:
        print("Your password looks great!")
