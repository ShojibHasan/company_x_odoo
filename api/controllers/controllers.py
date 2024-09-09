# -*- coding: utf-8 -*-
# from odoo import http


# class Api(http.Controller):
#     @http.route('/api/api', auth='public')
#     def index(self, **kw):
#         return "Hello, world"

#     @http.route('/api/api/objects', auth='public')
#     def list(self, **kw):
#         return http.request.render('api.listing', {
#             'root': '/api/api',
#             'objects': http.request.env['api.api'].search([]),
#         })

#     @http.route('/api/api/objects/<model("api.api"):obj>', auth='public')
#     def object(self, obj, **kw):
#         return http.request.render('api.object', {
#             'object': obj
#         })
