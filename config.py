import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "supersecretkey"
    SQLALCHEMY_DATABASE_URI = "sqlite:///site.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mail config (use Gmail app password)
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True

    MAIL_USERNAME = 'aravindjr84@gmail.com'  # Replace with your Gmail
    MAIL_PASSWORD = 'wloc yqfu vysf xprb'  # change to Gmail app password

    # Google reCAPTCHA
    RECAPTCHA_SITE_KEY = "6LcrndMrAAAAAHwuyNQTF_xPJL7IE4hph3uCCol1"  # from Google
    RECAPTCHA_SECRET_KEY = "6LcrndMrAAAAALS9uo5OOlaTQwJJF-bPzuJA74a5"  # from Google

    # CSRF secret
    WTF_CSRF_SECRET_KEY = os.environ.get("WTF_CSRF_SECRET_KEY") or "anothersecret"





