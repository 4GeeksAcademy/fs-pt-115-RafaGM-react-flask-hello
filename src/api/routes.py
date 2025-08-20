"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    if not data ('email') or not ('password'):
        return jsonify({'msg' : 'email and password are requiered'}), 400
    
    existing_user = db.session.execute (db.select(User).where(
        User.email == data('email')
    )).scalar_one_or_none()

    if existing_user:
        return jsonify({'msg' : 'user with this email already exist'}), 400
    
    new_user = User(email = data['email'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.sesseion.commit()

    return jsonify({'msg' : 'User created successfully'}), 201

@api.route('/loging', method = ['POST'])
def login():
    data = request.get_json()

    if not data ('email') or not ('password'):
        return jsonify({'msg' : 'email and password are requiered'}), 400

    user = db.session.execute (db.select(User).where(
        User.email == data('email')
    )).scalar_one_or_none()

    if user is None:
        return jsonify({'msg' : 'invalid email or password' }), 401
    
    if user.check_password(data ['password']):
        return jsonify ({'msg' : login successful}) , 200
    else:
        return jsonify({'msg' : 'invalid email or password'})
    
    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token, "user_id": user.id}), 200


@api.route("/private", methods=["GET"])
@jwt_required()
def private():
    user_id = get_jwt_identity()
    user = db.session.get(User, user_id)

    if user is None:
        return jsonify({"msg": "user not found"}), 404

    return jsonify({"msg": "This is a private route", "email": user.email}), 200
   


