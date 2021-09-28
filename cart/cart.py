"""
Importing the necessary Libraries
"""
from flask import Flask, render_template, redirect, url_for
from flask import Blueprint
import bcrypt
from flask_pymongo import PyMongo
import jwt
from bson.json_util import dumps
import json
import bson.errors
import jwt
from bson.objectid import ObjectId
import os
from flask import jsonify, request
import base64
from urllib import parse


from pymongo import MongoClient

from flask_jwt_extended import JWTManager, jwt_required, create_access_token

import config
import werkzeug.exceptions as ex
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from base64 import b64decode


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
curr_dir=os.path.dirname (os.path.realpath (__file__))

def decrypt_data(inputdata, code="123456"):
  #urldecode
  data=parse.unquote (inputdata)
  #base64decode
  data=base64.b64decode (data)
  private_key=RSA.importKey (
    open (curr_dir + "/my_private_rsa_key.bin"). read (),    passphrase=code
  )
  #Use pkcs1_v1_5 instead of pkcs1_oaep
  #If pkcs1_oaep is used, the data encrypted by jsencrypt.js on the front end cannot be decrypted
  cipher_rsa=PKCS1_v1_5.new (private_key)
  #When decryption fails,Will return sentinel
  #sentinel=none
  ret=cipher_rsa.decrypt (data, "none")
  return ret

# TODO ADD SESSION ID, SO IT COULD BE SENT FROM FRONTEND
@cart_bp.route("/addToCart/", methods=["POST","GET"])
# @jwt_required()
def addCart():
    try:
        """
        Using Json body
        """
        oid = request.values.get("oid")
        print(oid)
        newOid = decrypt_data(oid)
        print(newOid.decode())
        token = request.values.get("token")
        print(token, "isToken")
        newToken = decrypt_data(token)
        print(newToken, "MY TOKEN")
        getNewToken = newToken.decode() + ".appleMango"
        decoded = jwt.decode(getNewToken, options={"verify_signature":False})
        print(decoded)
        data = config.items.find_one({ "_id": ObjectId(newOid.decode())})
        category = data["category"]
        brand = data["brand"]
        model = data["model"]
        price =  data["price"]
        quantity = "784783532788723"

        # quantity = request.form['quantity']
        user_id = "kaushalgawri"
        user_name = decoded['email']

        item_data = dict(category=category, brand=brand, model=model, price=price, quantity=quantity, user_id=user_id, user_name=user_name)
        config.cart.insert_one(item_data)
        print("DONE")
        print("hougya")
        return redirect(url_for('cart_bp.getCartDetails'))
        # return render_template("logged_in.html")
        return jsonify(message="Item Added Successfully", flag=True), 201

    except (ex.BadRequestKeyError, KeyError):
        print("Hello")
        return internal_error()
    
@cart_bp.route("/editCart/<oid>", methods=["POST"])
# @jwt_required()
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

@cart_bp.route("/deleteCart/", methods=["POST"])
# @jwt_required()
def deleteCart():
    try:
        """
        Using Json body
        """
        oid = request.values.get("oid")
        newOid = decrypt_data(oid)
        config.cart.delete_one({ "_id": ObjectId(newOid.decode())})

        return redirect(url_for('cart_bp.getCartDetails'))

    except (ex.BadRequestKeyError, KeyError):
        return internal_error()

@cart_bp.route("/cart", methods=["POST","GET"])
def getCartDetails():

    data = config.cart.find({ "user_name": "ali_tariq1911@Hotmail.com"})
    print(data)
    filter = data
    result = dumps(data)
    res = json.loads(result)
    numberOfelements = len(res)

    return render_template("cart.html", items=res, numberOfelements=numberOfelements)