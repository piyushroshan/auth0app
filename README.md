# Auth0 OAuth Python App

This is a Flask application that demonstrates OAuth2 authentication using Auth0.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file with your Auth0 credentials:
```
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
```

3. Run the application:
```bash
python app.py
```

4. Visit http://localhost:5000 in your browser to test the login functionality.

## Features
- OAuth2 authentication with Auth0
- Secure session management
- User profile display after login
