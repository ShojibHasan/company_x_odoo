import jwt
from datetime import datetime, timedelta
import secrets
from odoo import http
from odoo.http import request,Response


SECRET_KEY = secrets.token_hex(32)
ALGORITHM = 'HS256'

def generate_jwt_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


def jwt_required(func):
    def wrapper(*args, **kwargs):
        auth_header = request.httprequest.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]  # Extract token after 'Bearer'
            user_payload = decode_jwt_token(token)  # Decode token to get user_id
            if user_payload:
                # Fetch user from the database using user_id from payload
                user_id = user_payload.get('user_id')
                user = request.env['res.users'].sudo().browse(user_id)

                if user.exists():
                    # Update the request environment with the authenticated user
                    request.update_env(user=user)
                    return func(*args, **kwargs)

        # If token is invalid or missing, return 401 Unauthorized
        return Response("Unauthorized", status=401)

    return wrapper

# Function to validate JWT token
def validate_jwt_token(token):
    try:
        # Decode the token to verify its validity
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload.get('user_id')
        # Ensure the user exists in the system
        user = request.env['res.users'].sudo().browse(user_id)
        if not user:
            return None
        return user
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

class CustomerAuthentication(http.Controller):
    @http.route('/api/customer/login', type='json', auth='none', methods=['POST'])
    def customer_login(self, **kwargs):
        # Retrieve email and password from JSON request
        json_data = request.httprequest.get_json()
        email = json_data.get('email')
        password = json_data.get('password')

        # Get the current database name
        db_name = request.session.db
        # Authenticate the user with email (login), password, and database
        user_id = request.env['res.users'].sudo().authenticate(db_name, email, password, {})

        if user_id:
            # If authentication is successful, generate a JWT token
            token = generate_jwt_token(user_id)
            return {'status': 'success', 'token': token}
        else:
            return {'status': 'error', 'message': 'Invalid credentials'}

    @http.route('/api/customer/logout', type='json', auth='none', methods=['POST'])
    def customer_logout(self, **kwargs):
        print("Logout")
        # Get the Authorization header from the request
        auth_header = request.httprequest.headers.get('Authorization')

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            user = validate_jwt_token(token)

            if user:
                # If user is authenticated with a valid token, perform logout actions if needed
                return {'status': 'success', 'message': 'Logged out successfully'}
            else:
                return {'status': 'error', 'message': 'Invalid token'}
        else:
            return {'status': 'error', 'message': 'Authorization header missing or invalid'}