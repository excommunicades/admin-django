# django-admin  ✅
![admin-django image](https://raw.githubusercontent.com/excommunicades/admin-django/main/django-admin.png)

## DESCRIPTION: 

This project provides a RESTful API for managing user authentication and registration. Built using Django and Django REST Framework, it implements secure JWT-based user management, including functionalities for user registration, login, password reset, and email verification.

This project serves as a guide to building a custom User Authentication API with JWT tokens for secure and scalable applications.

## This project is an example how to create a custom django admin using  Django REST Framework and drf-simple-jwt. The code serves as a practical guide to the following concepts:

* **User Registration and Authentication: Secure JWT authentication for users, allowing them to register, log in, and interact with protected endpoints.**
* **Custom User Model: Extends Django’s built-in user model to add additional fields and customize user behavior.**
* **Password Reset Mechanism: Supports a secure password reset flow via email, ensuring users can recover access to their accounts.**
* **Email Verification: An email verification process after registration to activate the user account.**
* **Error Handling: Implements robust error handling with detailed responses for validation errors.**

## Key Features 💡

- **User Registration:** Allows new users to sign up by providing a username, email, and password.
- **User Login:** Users can authenticate by submitting their username and password to receive a JWT access token.
- **Password Reset:** Users can request a password reset email and confirm their new password with a token.
- **Email Verification:** New users must verify their email address through a token sent to their inbox.
- **JWT Authentication:** Secure access to the API via JSON Web Tokens, allowing stateless authentication.

# Installation Guide 📕:

1. **Clone the repository:** ```git clone https://github.com/excommunicades/admin-django.git``` -> ```cd django-admin```
2. **Install dependencies:** ```pip install -r requirements.txt```
3. **Create database migrations:** ```python3 manage.py makemigrations```
4. **Apply database migrations:** ```python3 manage.py migrate```
5. **Run the development server:** ```python3 manage.py runserver```

### API Endpoints

- **POST** /auth/register/: Register a new user by providing a username, email, and password. 🟢
- **POST** /auth/login/: Authenticate an existing user and receive a JWT token. 🟢
- **POST** /auth/reset-password/: Request a password reset email by providing the user’s email address. 🟢
- **POST** /auth/reset-password-confirm/{uidb64}/{token}/: Confirm the password reset by submitting the new password and the reset token. 🟢
- **POST** /auth/verify-email/{token}/: Verify the user's email using the token received after registration. 🟢

# Stopping the Services 🚪

1. **To stop the server:** ```python3 manage.py stop OR Ctrl+C```

# Conclusion

This application provides a secure, scalable, and easily integrable user authentication system. With JWT authentication, users can register, log in, and manage their accounts in a safe environment. The API is built with extensibility in mind and can be integrated into larger Django-based applications.

## Authors 😎

- **Stepanenko Daniil** - "django-admin"
