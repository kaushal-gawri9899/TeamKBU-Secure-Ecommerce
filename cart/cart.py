"""
Importing the necessary Libraries
"""
from flask import Flask, render_template, redirect, url_for
from flask import Blueprint
from flask.globals import session
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

def returnEmail(getNewToken):
    decrypted_Token = decrypt_data(getNewToken)
    getNewToken = decrypted_Token.decode() + ".appleMango"
    decoded = jwt.decode(getNewToken, options={"verify_signature":False})
    return decoded['email']

def userExists():
    if session['token'] == None:
        return False

    user_email = returnEmail(session['token'])

    current_user = config.zhiffy.find_one({'email': user_email})
    result = dumps(current_user)
    res = json.loads(result)

    if res:
        return True

    return False

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

@cart_bp.route("/addToCart/", methods=["POST","GET"])
def addCart():
    try:
        """
        Using Json body
        """

        if not userExists():
            return redirect(url_for('user_bp.login'))

        oid = request.values.get("oid")
        newOid = decrypt_data(oid)
        token = request.values.get("token")
        user_email = returnEmail(token)
        data = config.items.find_one({ "_id": ObjectId(newOid.decode())})
        category = data["category"]
        brand = data["brand"]
        model = data["model"]
        price =  data["price"]
        quantity = "1"

        user_id = "kaushalgawri"
        user_name = user_email

        item_data = dict(category=category, brand=brand, model=model, price=price, quantity=quantity, user_id=user_id, user_name=user_name)
        config.cart.insert_one(item_data)
        return redirect(url_for('cart_bp.getCartDetails'))
        # return render_template("logged_in.html")
        return jsonify(message="Item Added Successfully", flag=True), 201

    except (ex.BadRequestKeyError, KeyError):
        print("Hello")
        return internal_error()
    
@cart_bp.route("/editCart/", methods=["POST"])
# @jwt_required()
def editCart():
    try:
        """
        Using Json body
        """
        if not userExists():
            return redirect(url_for('user_bp.login'))

        oid = request.values.get('OID')
        quantity = request.values.get('quantity')
        print(request.values.get('OID'))
        print(request.values.get('quantity'))
        # print(quantity)

        encrypted_quantity = request.values.get("quantity")
        decrypted_quantity = decrypt_data(encrypted_quantity)
        newOid = decrypt_data(oid)
        # # print(newOid)
        data = config.cart.find_one({ "_id": ObjectId(newOid.decode())})
        # # print(decrypted_quantity)
        # # print(data)
        filter = data
        # # print("")  
        # # # Values to be updated.
        newvalues = { "$set": { 'quantity': int(decrypted_quantity.decode()) } }
        config.cart.update_one(filter, newvalues) 
        return redirect(url_for('product_bp.getAllItems'))
        # return redirect(url_for('cart_bp.getCartDetails'))
        # return jsonify(message="Item Updated Successfully", flag=True), 201

    except (ex.BadRequestKeyError, KeyError):
        return internal_error()

@cart_bp.route("/deleteCart/", methods=["POST"])
# @jwt_required()
def deleteCart():
    try:
        """
        Using Json body
        """
        if not userExists():
            return redirect(url_for('user_bp.login'))

        oid = request.values.get("oid")
        print(oid, "I WAS CALLED")
        newOid = decrypt_data(oid)
        config.cart.delete_one({ "_id": ObjectId(newOid.decode())})

        return redirect(url_for('cart_bp.getCartDetails'))

    except (ex.BadRequestKeyError, KeyError):
        return internal_error()

@cart_bp.route("/cart", methods=["POST","GET"])
def getCartDetails():
    if not userExists():
        return redirect(url_for('user_bp.login'))

    getToken = session['token']
    getEmail = returnEmail(getToken)
    data = config.cart.find({ "user_name": getEmail})
    result = dumps(data)
    res = json.loads(result)
    print(res)
    numberOfelements = len(res)

    return render_template("cart.html", items=res, numberOfelements=numberOfelements)