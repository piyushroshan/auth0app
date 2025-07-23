from flask import Flask, redirect, url_for, request, render_template, jsonify
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
import jwt
import requests
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')

AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
API_AUDIENCE = os.getenv('AUTH0_CLIENT_ID')  # Use your API audience if different

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=os.getenv('AUTH0_CLIENT_ID'),
    client_secret=os.getenv('AUTH0_CLIENT_SECRET'),
    api_base_url=f'https://{os.getenv("AUTH0_DOMAIN")}',
    access_token_url=f'https://{os.getenv("AUTH0_DOMAIN")}/oauth/token',
    authorize_url=f'https://{os.getenv("AUTH0_DOMAIN")}/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{os.getenv("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

def get_jwks():
    jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    return requests.get(jwks_url).json()

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth:
            return jsonify({'error': 'Authorization header is expected'}), 401
        parts = auth.split()
        if parts[0].lower() != 'bearer':
            return jsonify({'error': 'Authorization header must start with Bearer'}), 401
        elif len(parts) == 1:
            return jsonify({'error': 'Token not found'}), 401
        elif len(parts) > 2:
            return jsonify({'error': 'Authorization header must be Bearer token'}), 401
        token = parts[1]
        try:
            jwks = get_jwks()
            unverified_header = jwt.get_unverified_header(token)
            rsa_key = {}
            for key in jwks['keys']:
                if key['kid'] == unverified_header['kid']:
                    rsa_key = {
                        'kty': key['kty'],
                        'kid': key['kid'],
                        'use': key['use'],
                        'n': key['n'],
                        'e': key['e']
                    }
            if rsa_key:
                payload = jwt.decode(
                    token,
                    key=jwt.algorithms.RSAAlgorithm.from_jwk(rsa_key),
                    audience=API_AUDIENCE,
                    issuer=f"https://{AUTH0_DOMAIN}/",
                    algorithms=['RS256']
                )
                return f(payload, *args, **kwargs)
        except Exception as e:
            return jsonify({'error': str(e)}), 401
        return jsonify({'error': 'Unable to parse authentication token.'}), 401
    return decorated

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    origin = request.url_root.rstrip('/')
    callback_url = f"{origin}/callback"
    # if AUTH0_CALLBACK_URL is set, use it instead of the default
    if os.getenv('AUTH0_CALLBACK_URL')
        callback_url = os.getenv('AUTH0_CALLBACK_URL')
    return auth0.authorize_redirect(callback_url)

@app.route('/callback')
def callback():
    token = auth0.authorize_access_token()
    id_token = token.get('id_token')
    # Redirect to /profile with the JWT in the URL fragment
    return redirect(f"/profile#id_token={id_token}")

@app.route('/logout')
def logout():
    # For JWT-based auth, logout is handled on the frontend by removing the JWT
    return redirect('/')

@app.route('/api/profile')
@requires_auth
def api_profile(payload):
    return jsonify({
        "user_id": payload.get("sub"),
        "name": payload.get("name"),
        "picture": payload.get("picture"),
        "email": payload.get("email"),
        "raw": payload
    })

@app.route('/profile')
def profile():
    return render_template('profile.html')

if __name__ == '__main__':
    import os
    cert_file = 'cert.pem'
    key_file = 'key.pem'
    if os.path.exists(cert_file) and os.path.exists(key_file):
        app.run(debug=True, port=5555, ssl_context=(cert_file, key_file))
    else:
        print(f"SSL certificates not found. Please generate cert.pem and key.pem in the project directory.\n"
              f"You can generate them with:\n"
              f"  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'\n"
              f"Running without SSL...")
        app.run(debug=True, host="0.0.0.0", port=5555)
