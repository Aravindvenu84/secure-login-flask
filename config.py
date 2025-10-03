import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "supersecretkey"
    SQLALCHEMY_DATABASE_URI = "sqlite:///site.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mail config (use Gmail app password)
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True

    MAIL_USERNAME = 'aBCD@gmail.com'  #REMOVED  BECAUSE OF PRIVACY

    MAIL_PASSWORD = ''  #REMOVED  BECAUSE OF PRIVACY

    # Google reCAPTCHA
    RECAPTCHA_SITE_KEY = "9YEFHDIJSEGOJOEJSJG'OHJEPJHJOJJH"  #REMOVED  BECAUSE OF PRIVACY

    RECAPTCHA_SECRET_KEY = "YURGWWIUHIFOJPOGIOE9U9892IRHENDJI89443J"  # #REMOVED  BECAUSE OF PRIVACY


    # CSRF secret
    WTF_CSRF_SECRET_KEY = os.environ.get("WTF_CSRF_SECRET_KEY") or "anothersecret"





