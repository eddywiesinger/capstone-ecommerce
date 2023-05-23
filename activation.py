from itsdangerous import URLSafeTimedSerializer


def generate_confirmation_token(email):
    from main import application
    serializer = URLSafeTimedSerializer(application.config['SECRET_KEY'])
    return serializer.dumps(email, salt=application.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    from main import application
    serializer = URLSafeTimedSerializer(application.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=application.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email
