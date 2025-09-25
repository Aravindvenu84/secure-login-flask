<h1>Flask Secure Authentication System</h1>
  
<h2>Introduction</h2>

This is a secure and user-friendly authentication system built with Flask. It provides robust features for user registration, login, and password management, while prioritizing security. The system includes email verification via OTP, strong password enforcement, CAPTCHA validation, and secure password reset flows. Flash messages inform users of login issues, such as incorrect credentials or unverified emails, ensuring a clear and guided experience.

<h2>Features

<h3>User Registration</h3>

Secure registration with email and strong password requirements (minimum 8 characters, includes uppercase, lowercase, number, and special character).

Sends a One-Time Password (OTP) to verify email.

OTP valid for 5 minutes and maximum 2 requests per hour.

<h3>User Login</h3>

Validates email and password.

Includes Google reCAPTCHA verification.

Flash warnings for:

Incorrect email or password: "Email or password is incorrect."

Unverified email: "Please verify your email first."

Successful login creates a session and redirects to the dashboard.

<h3>Password Reset</h3>

OTP-based password reset for registered users.

Enforces strong password validation.

OTP verification required to update password.

<h3>Security</h3>

CSRF protection using Flask-WTF.

Passwords hashed securely with Werkzeug PBKDF2-SHA256.

Flash messages for warnings, errors, and success feedback.

<h3>Dashboard</h3>

Only accessible to authenticated users.

<h3>Logout</h3>

Securely ends the user session.
<h2>Usage</h2>

Register with your email and a strong password.

Verify your email using the OTP sent to your inbox.

Login using your credentials.

If you forget your password, use the Forgot Password flow to reset it via OTP.
<h2>Notes</h2>

OTP requests limited to 2 per hour.

Passwords stored hashed for security.

Flash messages guide users with clear warnings and success notifications.

Designed for secure, user-friendly authentication with minimal setup.
