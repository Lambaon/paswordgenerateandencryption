import secrets
import string


def generate_strong_password(length=16, use_uppercase=True, use_digits=True, use_special=True) -> str:
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation.replace('"', '').replace("'", '')

    password = []
    if use_uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_special:
        password.append(secrets.choice(string.punctuation.replace('"', '').replace("'", '')))

    remaining_length = length - len(password)
    password.extend(secrets.choice(characters) for _ in range(remaining_length))

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


if __name__ == "__main__":
    print(generate_strong_password(20))
