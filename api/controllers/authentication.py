import jwt
from datetime import datetime, timedelta
import secrets
from odoo import http
from odoo.http import request

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


class CustomerAuthentication(http.Controller):
    @http.route('/api/customer/login', type='json', auth='none', methods=['POST'])
    def customer_login(self, **kwargs):
        print("Inside customer_login")
        email = kwargs.get('email')
        password = kwargs.get('password')
        print(f"email: {email} password: {password}")
        user = request.env['res.users'].sudo().search([('login', '=', email)])
        print("user: ",user)
        if user and user.sudo().check_password(password):
            token = generate_jwt_token(user.id)
            return {
                'token': token.decode('utf-8')
            }
        return {
            'error': 'Invalid credentials'
        }

    @http.route('/api/customer/logout', type='json', auth='none', methods=['POST'])
    def customer_logout(self, **kw):
        token = kw.get('token')
        payload = decode_jwt_token(token)
        if payload.get('user_id'):
            return {
                'message': 'Successfully logged out'
            }
        return {
            'error': 'Invalid token'
        }