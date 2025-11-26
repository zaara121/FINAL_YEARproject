import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret')

    
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/smartstore')

   
  

    # SMTP / Email settings (used for OTP)
    SMTP_HOST = os.environ.get('SMTP_HOST', '')          # e.g. smtp.office365.com or smtp.gmail.com
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))  # 587 for TLS, 465 for SSL
    SMTP_USER = os.environ.get('SMTP_USER', '')          # your email address
    SMTP_PASS = os.environ.get('SMTP_PASS', '')          # app password or SMTP password
    SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER)   # From address (optional)
    SMTP_USE_SSL = os.environ.get('SMTP_USE_SSL', '0') == '1'  # '1' to use SMTP_SSL on connect
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', '1') == '1'  # '1' to starttls after connect

    SMTP_SERVER = "smtp.office365.com"
    SMTP_PORT = 587
    SMTP_USERNAME = "your@company.com"
    SMTP_PASSWORD = "app-password"
    MAIL_FROM = "no-reply@yourdomain.com"
