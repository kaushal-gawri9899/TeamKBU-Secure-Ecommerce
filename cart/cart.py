"""
Importing the necessary Libraries
"""
from flask import Flask
from flask import Blueprint
import bcrypt
from flask_pymongo import PyMongo

from bson.json_util import dumps
import json
import bson.errors

from bson.objectid import ObjectId

from flask import jsonify, request

from pymongo import MongoClient

from flask_jwt_extended import JWTManager, jwt_required, create_access_token

import config
import werkzeug.exceptions as ex

"""
Creating a blueprint for all the product routes
This blueprint would be registered in main application
"""
cart_bp = Blueprint('cart_bp', __name__)


"""
Insert Product API route : Adds a product or items to the collection with pre decided attributes. 
Pre decided attributes are used to the best of my knowledge
Validates empty string for details and converts the values to a dictionary
Dictionary is then added to the "items" collection
Returns a success message
A decorator is added to add security for the current method, user with only access token provided during login can perform operation
"""
@cart_bp.route("/addToCart/<oid>", methods=["POST"])
@jwt_required()
def addCart(oid):
    try:
        """
        Using Json body
        """
        data = config.items.find_one({ "_id": ObjectId(oid)})
        print(data)
        category = data["category"]
        brand = data["brand"]
        model = data["model"]
        price =  data["price"]
        quantity = "2"
        # quantity = request.form['quantity']
        user_id = "session_id"
        user_name = "name"

        item_data = dict(category=category, brand=brand, model=model, price=price, quantity=quantity, user_id=user_id, user_name=user_name)
        config.cart.insert_one(item_data)
        return jsonify(message="Item Added Successfully", flag=True), 201

    except (ex.BadRequestKeyError, KeyError):
        return internal_error()
    
@cart_bp.route("/editCart/<oid>", methods=["POST"])
@jwt_required()
def editCart(oid):
    try:
        """
        Using Json body
        """
        data = config.cart.find_one({ "_id": ObjectId(oid)})
        print(data)
        filter = data
  
        # Values to be updated.
        newvalues = { "$set": { 'quantity': 25 } }
        config.cart.update_one(filter, newvalues) 
  
        return jsonify(message="Item Updated Successfully", flag=True), 201

    except (ex.BadRequestKeyError, KeyError):
        return internal_error()

@cart_bp.route("/deleteCart/<oid>", methods=["POST"])
@jwt_required()
def deleteCart(oid):
    try:
        """
        Using Json body
        """
        
        config.cart.delete_one({ "_id": ObjectId(oid)})

        return jsonify(message="Item Deleted Successfully", flag=True), 201

    except (ex.BadRequestKeyError, KeyError):
        return internal_error()