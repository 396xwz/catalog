import re 
import string

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EM_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def verify_username(username):
    return USER_RE.match(username)


def verify_email(email):
    if email == '':
        return True
    else:
        return EM_RE.match(email)


