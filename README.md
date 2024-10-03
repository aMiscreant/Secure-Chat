# Secure Chat


# Secure Messaging System

This is a secure messaging system built using Flask, providing robust security measures including user authentication, message encryption, two-factor authentication, and more.

## Features

- **User Registration**: New users can create an account with strong password validation.
- **Login with Two-Factor Authentication**: Users log in with their credentials and verify via OTP.
- **Secure Messaging**: Messages are encrypted using AES encryption.
- **Message Timestamps**: Each message is accompanied by a timestamp.
- **User Profile Management**: Users can update their passwords.
- **Logout Functionality**: Users can log out of the chat.
- **Message Deletion**: Users can delete their messages.
- **Contact List**: Users can maintain a contact list.
- **User Activity Logging**: User activities are logged for security.
- **User Authentication Lockout**: Accounts are temporarily locked after multiple failed login attempts.

## Technologies Used

- Python
- Flask
- Flask-WTF (CSRF protection)
- Flask-Mail (Email functionality)
- Flask-Limiter (Rate limiting)
- Cryptography (Message encryption)
- OTP (Two-factor authentication)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure_messaging.git
   cd secure_messaging

2. Install the required packages:

pip install -r requirements.txt


3. Configure email settings in app.py:

Set your SMTP server details, username, and password.



4. Run the application:

python app.py


5. Access the application in your browser at http://127.0.0.1:5000.



Security Measures

CSRF Protection: Prevents Cross-Site Request Forgery attacks.

Rate Limiting: Limits the number of login attempts to prevent brute-force attacks.

Encryption: Messages are encrypted using AES encryption.

Secure Cookies: Cookies are set to be HTTP-only and secure.


License

This project is licensed under the MIT License.

### Final Notes

- Remember to update your email configuration in `app.py` to match your SMTP server.
- For a production environment, consider using a proper database for user management and message storage instead of an in-memory dictionary.
- Ensure your environment is properly set up to run Flask applications, including having the necessary packages installed.

