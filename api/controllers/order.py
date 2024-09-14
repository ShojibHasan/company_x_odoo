from odoo import http
from .authentication import jwt_required,validate_jwt_token
from odoo.http import request,Response
import json


class OrderAPI(http.Controller):
    @http.route('/api/v1/order', type='http', auth='none', methods=['GET'])
    @jwt_required
    def list_orders(self, **kwargs):
        # # Retrieve the Authorization header
        auth_header = request.httprequest.headers.get('Authorization')

        # Extract token from the 'Authorization' header
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
            user = validate_jwt_token(token)

            if user:
                # Retrieve orders for the user
                orders = request.env['sale.order'].sudo().search([('partner_id', '=', user.partner_id.id)])
                order_data = [{'id': order.id, 'name': order.name, 'amount': order.amount_total} for order in orders]
                return request.make_response(json.dumps({'status': 'success', 'orders': order_data}),
                                             headers=[('Content-Type', 'application/json')])
            else:
                return request.make_response(json.dumps({'status': 'error', 'message': 'Invalid token'}),
                                             headers=[('Content-Type', 'application/json')])
        else:
            return request.make_response(json.dumps({'status': 'error', 'message': 'Authorization header missing'}),
                                         headers=[('Content-Type', 'application/json')])

    @http.route('/api/v1/order/<int:order_id>', type='http', auth='none', methods=['GET'])
    @jwt_required
    def get_order(self, order_id, **kwargs):
        order = request.env['sale.order'].sudo().browse(order_id)
        if order.exists():
            order_data = {
                'id': order.id,
                'name': order.name,
                'amount': order.amount_total
            }
            return request.make_response(
                json.dumps({'status': 'success', 'order': order_data}),
                headers=[('Content-Type', 'application/json')]
            )
        else:
            return request.make_response(
                json.dumps({'status': 'error', 'message': 'Order not found'}),
                headers=[('Content-Type', 'application/json')],
                status=404
            )