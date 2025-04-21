from bcrypt import hashpw, gensalt, checkpw

def hash_password(password: str) -> str:
    password = password.encode('utf-8')
    hashed_password = hashpw(password, gensalt())
    hashed_password = hashed_password.decode('utf-8')
    return hashed_password

def check_password(password: str, hashed_password: str) -> bool:
    password = password.encode('utf-8')
    hashed_password = hashed_password.encode('utf-8')
    return checkpw(password, hashed_password)