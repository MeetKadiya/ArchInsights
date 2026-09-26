# tests/sample_codebase/pkg_b/user_service.py

def get_user(user_id):
    return {"id": user_id, "name": "Test User"}

def update_user_email(user_id, email):
    if not email or "@" not in email:
        return False
    return True
