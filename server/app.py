from flask import Flask, request, session, jsonify
from flask_restful import Resource, Api
from models import db, User, Recipe
from config import app, db, api
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)
app.secret_key = app.config.get("SECRET_KEY", "dev")


def current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None


def require_login():
    if not session.get('user_id'):
        return {'error': 'Unauthorized'}, 401


def user_to_dict(user: User):
    return {
        'id': user.id,
        'username': user.username,
        'bio': user.bio,
        'image_url': user.image_url,
    }


def recipe_to_dict(recipe: Recipe):
    return {
        'id': recipe.id,
        'title': recipe.title,
        'instructions': recipe.instructions,
        'minutes_to_complete': recipe.minutes_to_complete,
        'user_id': recipe.user_id,
    }


class Signup(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'errors': ['username and password required']}, 422

        try:
            user = User(
                username=username,
                bio=data.get('bio'),
                image_url=data.get('image_url'),
            )
            user.password_hash = password
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            return user_to_dict(user), 201
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['username must be unique']}, 422


class CheckSession(Resource):
    def get(self):
        user = current_user()
        if not user:
            return {'error': 'Unauthorized'}, 401
        return user_to_dict(user), 200


class Login(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if not user:
            return {'error': 'Unauthorized'}, 401

        try:
            if bcrypt.check_password_hash(user._password_hash, password):
                session['user_id'] = user.id
                return user_to_dict(user), 200
        except Exception:
            pass

        return {'error': 'Unauthorized'}, 401


class Logout(Resource):
    def delete(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        session['user_id'] = None
        session.clear()
        return {}, 204


class RecipeIndex(Resource):
    def get(self):
        auth = require_login()
        if auth:
            return auth
        user = current_user()
        recipes = [recipe_to_dict(r) for r in user.recipes]
        return recipes, 200

    def post(self):
        auth = require_login()
        if auth:
            return auth

        user = current_user()
        data = request.get_json() or {}
        title = data.get('title')
        instructions = data.get('instructions')
        minutes = data.get('minutes_to_complete')

        errors = []
        if not title:
            errors.append('title required')
        if not instructions or len(instructions) < 50:
            errors.append('instructions must be at least 50 characters')
        if errors:
            return {'errors': errors}, 422

        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes
        )
        recipe.user = user
        db.session.add(recipe)
        db.session.commit()
        return recipe_to_dict(recipe), 201


api.add_resource(Signup, '/signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(RecipeIndex, '/recipes')