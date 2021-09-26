"""
Importing the necessary Libraries
"""
from flask import Flask
from flask import Blueprint
import bcrypt
import pymongo.errors
from flask_pymongo import PyMongo

from bson.json_util import dumps

from bson.objectid import ObjectId

from flask import jsonify, request, render_template, redirect, url_for

from pymongo import MongoClient

from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import config

import werkzeug.exceptions as ex

"""
Creating a blueprint for all the user routes
This blueprint would be registered in main application
"""
user_bp = Blueprint('user_bp', __name__)


"""
Register API route : Used for registering users to the system and adding to Zhiffy collection
Uses bcrypt python library to hash the passwords that user enters using random salts after the password is encoded
Returns an access token with a successfull registeration message
Error handling for empty strings could be added using a simple if conditions but skipped for now
As suggested in specification, details from form data acts as input.
"""
@user_bp.route("/register", methods=["POST","GET"])
def register():
    if request.method == 'POST':
        try:
            user_email = request.form["email"]
        
            is_inValid = config.zhiffy.find_one({"email": user_email})

            if is_inValid:
                return jsonify(message="Cannot Register User. Email Already Used", flag=False), 409
            else:
                user_name = request.form["name"]
                user_password = request.form["password"]
                if user_name and user_password and user_email:
                    password_new = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt())
                    user_data = dict(name=user_name, email=user_email, password=password_new)
                    config.zhiffy.insert_one(user_data)
                    user_access_token = create_access_token(identity=user_email)

                    # return jsonify(message="Voila! User Registration Successful.", access_token=user_access_token, flag=True), 201
                    return render_template("login.html")
                else:
                    return jsonify(message="Empty Fields Found. Please Fill all Details", flag=False), 404
        
        except (ex.BadRequestKeyError, KeyError):
            return internal_error()
    else:
        return render_template("register.html")

@user_bp.errorhandler(500)
def internal_error(error=None):
    message= {
        'status': 404,
        'message': "Invalid Fields Provided. Please Retry!"
    }

    resp = jsonify(message)
    return resp


"""
Login API route : Used for providing access to users for the system
Uses bcrypt python library to hash the passwords that user enters using random salts after the password is encoded
Hashed password is compared to the password stored in collection and authorization is completed
Returns an access token with a successfull login message
Access Token is used for authorizatioton in other methods
Error handling for empty strings could be added using a simple if conditions but skipped for now
As suggested in specification, login details are taken as json string
"""
@user_bp.route("/", methods=["POST","GET"])
def login():
    if request.method == 'POST':
        try:
            # data = request.get_json()
            # print(data['firstName'], "firstName")
            # print(request.form, "aaaaa")
            _json = request.json
            user_email = request.form["email"]
            user_password = request.form["password"]
            user_token = request.form["token"]
            print(user_token, "OUR TOKEN IS HERE")

            current_user = config.zhiffy.find_one({'email': user_email})
        
            if user_email and user_password:
                if current_user:
                    if bcrypt.hashpw(user_password.encode('utf-8'), current_user["password"]) == current_user["password"]:
                        user_access_token = create_access_token(identity=user_email)
                        # print(user_access_token)
                       
                        return redirect(url_for('product_bp.getAllItems'))
                        # return jsonify(message="Voila! User Successfully Logged In.", access_token=user_access_token, flag=True), 200
            else:
                return jsonify(message="Empty Fields Found. Please Fill all Details", flag=False), 404

            return jsonify(message="Invalid Credentials. Please Retry.", flag=False), 404
        
        except (ex.BadRequestKeyError, KeyError):
            return internal_error()
    
    else: 
        return render_template("login.html")


"""
Change User Detail API route : Used to update the details of user stored in collection
Uses PUT Http request to replace the current details with the newly updated one
Returns a success message
A decorator is added to add security for the current method, user with only access token provided during login can perform operation
"""
@user_bp.route("/changeUserDetails/<uid>", methods=["PUT"])
@jwt_required()
def changeUserDetail(uid):

    try:
        _json = request.json
        user_email = _json["email"]
        user_name = _json["name"]
        user_password = _json["password"]

        if user_email and user_name and user_password:
            hash_password = bcrypt.hashpw(user_password.encode('utf-8'), bcrypt.gensalt())

            update_user = config.zhiffy.update_one({'_id': ObjectId(uid)}, {"$set": {'email': user_email, 'name': user_name, 'password': hash_password}})

            return jsonify(message="User Details with Email {"+user_email+"} and ID {"+str(ObjectId(uid))+"} Updated.", flag=True), 200
        
        else:
            return jsonify(message="Invalid Details Provided. Please Retry.", flag=False), 404
    
    except (ex.BadRequestKeyError, KeyError):
        return internal_error()





