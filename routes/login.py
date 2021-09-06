from flask import Blueprint, Flask, jsonify, request, Response
from flask_pymongo import PyMongo
import os
from dotenv import load_dotenv
import json
import bcrypt
import jwt
from flask_cors import CORS, cross_origin
import cloudinary as Cloud
from cloudinary import uploader

load_dotenv()

app = Flask(__name__)

app.config['MONGO_URI'] = os.getenv('MONGO_URI')


index_blueprint = Blueprint('login', __name__)
mongo = PyMongo(app)

Cloud.config.update = ({
    'cloud_name': os.getenv('CLOUDINARY_CLOUD_NAME'),
    'api_key': os.getenv('CLOUDINARY_API_KEY'),
    'api_secret': os.getenv('CLOUDINARY_API_SECRET')
})


@index_blueprint.route("/signin", methods=["POST"])
def signin():
    add = mongo.db.user
    data = request.get_json(force=True)
    existUser = add.find_one({'email': data['email']})
    if(existUser):
        passwordCheck = bcrypt.checkpw(
            data['password'].encode('utf8'), existUser['password'])
        if(passwordCheck):
            existUser['_id'] = str(existUser['_id'])
            del existUser['password']
            return jsonify({'success': True, 'message': 'User Find!!!', 'user': existUser})
        else:
            return jsonify({'success': False, 'message': 'Invalid Email Or Password!!!'})
    else:
        return jsonify({'success': False, 'message': 'Invalid Email Or Password!!!'})


@index_blueprint.route("/signup", methods=["POST"])
def registerUser():
    add = mongo.db.user
    data = request.get_json(force=True)
    existUser = add.find_one({'email': data['email']})
    if(existUser):
        return jsonify({'success': False, 'message': 'User Already Exist!!!'})
    else:
        hashed_password = bcrypt.hashpw(
            data['password'].encode('utf8'), bcrypt.gensalt(12))
        encoded = jwt.encode(data, 'secretToken', algorithm='HS256')
        encoded = str(encoded).split("'")
        user = {
            'fname': data['fname'],
            'lname': data['lname'],
            'name': data['fname'] + " " + data['lname'],
            'phone': data['phone'],
            'email': data['email'],
            'address': data['address'],
            'country': data['country'],
            'city': data['city'],
            'zip': data['zip'],
            'password': hashed_password,
            'secretToken': encoded[0],
            'role': 'agent'
        }
        add_data = add.insert_one(user)
        user['_id'] = str(add_data.inserted_id)
        del user['password']
        del user['secretToken']
        return jsonify({'success': True, 'message': 'Successfully Registered', "secretToken": 'encoded', 'email': data['email'], 'user': user})
