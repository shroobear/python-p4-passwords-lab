#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()

        username = json.get('username')
        password = json.get('password')

        if not username or not password:
            return make_response(jsonify({'message': 'Username and password are required'}), 400)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return make_response(jsonify({'message': 'Username already exists'}), 400)

        user = User(
            username=username
        )
        user.password_hash = password

        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id

        return make_response(jsonify(user.to_dict()), 201)

class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session['user_id']).first()
        if user:
            return make_response(jsonify(user.to_dict()), 200)
        return make_response(jsonify({}), 204)

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        if not username or not password:
            return make_response(jsonify({'message': 'Username and password are required'}), 400)

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return make_response(jsonify(user.to_dict()), 200)
        else:
            return make_response(jsonify({'message': 'Invalid credentials'}), 401)


class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return make_response(jsonify({'message': '204: No content'}), 204)

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
