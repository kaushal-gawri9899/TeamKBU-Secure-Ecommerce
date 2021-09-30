"""
Importing the necessary Libraries
"""
from flask import Flask, render_template, redirect, url_for
from flask import Blueprint
from datetime import date, datetime
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
  data= base64.b64decode (data)
  private_key=RSA.importKey (
    open (curr_dir + "/my_private_rsa_key.bin"). read (),    passphrase=code
  )
  #Use pkcs1_v1_5 instead of pkcs1_oaep
  #If pkcs1_oaep is used, the data encrypted by jsencrypt.js on the front end cannot be decrypted
  cipher_rsa=PKCS1_v1_5.new(private_key)
  #When decryption fails,Will return sentinel
  #sentinel=none
  ret=cipher_rsa.decrypt (data, "none")
  return ret

def encrypt_data(inputdata, code="123456"):
  #urldecode
#   data=parse.unquote (inputdata)
# #   #base64decode
#   print("Data",data)
  data= base64.b64decode(inputdata)
#   print(data)
  private_key=RSA.importKey (
    open (curr_dir + "/my_private_rsa_key.bin"). read (),    passphrase=code
  )
  #Use pkcs1_v1_5 instead of pkcs1_oaep
  #If pkcs1_oaep is used, the data encrypted by jsencrypt.js on the front end cannot be decrypted
  cipher_rsa=PKCS1_v1_5.new(private_key)
  #When decryption fails,Will return sentinel
  #sentinel=none
  ret=cipher_rsa.encrypt(data)
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
        print("k",decrypted_quantity)
        newOid = decrypt_data(oid)
        print("n",newOid)
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

@cart_bp.route("/payment", methods=["POST"])
def payOrder():
   
    name = decrypt_data(request.values.get("cname")).decode()
    number = decrypt_data(request.values.get('cnum')).decode()
    expiry = decrypt_data(request.values.get('exp')).decode()
    cvv = decrypt_data(request.values.get('cvv')).decode()
    

    session_token = session['token']
    user_email = returnEmail(session_token)
    data = config.cart.find({ "user_name": user_email})
    res = json.loads(dumps(data))
    print(res)
    numberOfelements = len(res)
    print(numberOfelements)
    category_list = []
    brand_list = []
    model_list = []
    price_list = []
    quantity_list = []
    oid_list = []
    total_price = 0
    today = date.today()
    
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    current_date = datetime.strptime(str(today),"%Y-%m-%d")
    validate_date = datetime.strptime(str(expiry),"%m/%Y")
    # TODO: Error mesaage as date is bad
    if validate_date < current_date:
        return "Failure"

    for i in range(numberOfelements):
        if res[i]['_id']['$oid']:
            oid_list.append(res[i]['_id']['$oid'])
        if res[i]['category']:
            category_list.append(res[i]['category'])
        if res[i]['brand']:
            brand_list.append(res[i]['brand'])
        if res[i]['model']:
            model_list.append(res[i]['model'])
        if res[i]['price']:
            price_list.append(res[i]['price'])
            total_price += int(res[i]['price'])
        if res[i]['quantity']:
            quantity_list.append(res[i]['quantity'])
       

    user_data = dict(category=category_list, brand=brand_list, model=model_list, price=price_list, quantity=quantity_list, cname = name, cnum = number, cexpiry = expiry, cvv = cvv, user_email = user_email, total_price = total_price, date_ordered = dt_string )
    # print(category_list, brand_list, model_list, price_list, quantity_list)
    result = config.order.insert_one(user_data)
    # if result:
    #     print(result)
    #     for i in range(numberOfelements):
    #         config.cart.delete_one({ "_id": ObjectId(oid_list[i])})
    return "true"
@cart_bp.route("/deleteCart", methods=["POST"])
# @jwt_required()
def deleteCart():
    try:
        """
        Using Json body
        """
        if not userExists():
            return redirect(url_for('user_bp.login'))

        oid = request.values.get("oid")
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
    numberOfelements = len(res)

    return render_template("cart.html", items=res, numberOfelements=numberOfelements)

@cart_bp.route("/orders", methods=["POST","GET"])
def getOrderDetails():
    if not userExists():
        return redirect(url_for('user_bp.login'))

    getToken = session['token']
    getEmail = returnEmail(getToken)
    data = config.order.find({ "user_email": str(getEmail)})
    result = dumps(data)
    res = json.loads(result)
    numberOfelements = len(res)

    category_list = []
    brand_list = []
    model_list = []
    price_list = []
    quantity_list = []
    oid_list = []
    total_price_list = []
    date_ordered_list = []

    for i in range(numberOfelements):
        if res[i]['_id']['$oid']:
            oid_list.append(res[i]['_id']['$oid'])
        if res[i]['total_price']:
            val = str(res[i]['total_price'])
            if len(val) % 4:
                # not a multiple of 4, add padding:
                val += '=' * (4 - len(val) % 4) 
            total_price_list.append(val)
        if res[i]['date_ordered']:
            date_ordered_list.append(res[i]['date_ordered'])
        if res[i]['category'][0]:
            if len(res[i]['category'][0]) % 4:
                # not a multiple of 4, add padding:
                res[i]['category'][0] += '=' * (4 - len(res[i]['category'][0]) % 4) 
            category_list.append(res[i]['category'][0])
        if res[i]['brand'][0]:
            if len(res[i]['brand'][0]) % 4:
                # not a multiple of 4, add padding:
                res[i]['brand'][0] += '=' * (4 - len(res[i]['brand'][0]) % 4) 
            brand_list.append(res[i]['brand'][0])
        if res[i]['model'][0]:
            if len(res[i]['model'][0]) % 4:
                # not a multiple of 4, add padding:
                res[i]['model'][0] += '=' * (4 - len(res[i]['model'][0]) % 4) 
            model_list.append(res[i]['model'][0])
        if res[i]['price'][0]:
            if len(str(res[i]['price'][0])) % 4:
                # not a multiple of 4, add padding:
                res[i]['price'][0] += '=' * (4 - len(str(res[i]['price'][0])) % 4) 
            price_list.append(str(res[i]['price'][0]))
        if res[i]['quantity'][0]:
            val = str(res[i]['quantity'][0])
            if len(val) % 4:
                # not a multiple of 4, add padding:
                val += '=' * (4 - len(val) % 4) 
            quantity_list.append(val)
   
    encrypted_category_list = []
    encrypted_brand_list = []
    encrypted_model_list = []
    encrypted_price_list = []
    encrypted_quantity_list = []
    encrypted_oid_list = []
    encrypted_total_price_list = []
    encrypted_date_ordered_list = []

    for i in range(numberOfelements):
        print(i)
        encrypted_category_list.append(encrypt_data(category_list[i]))
        encrypted_brand_list.append(encrypt_data(brand_list[i]))
        encrypted_model_list.append(encrypt_data(model_list[i]))
        encrypted_price_list.append(encrypt_data(price_list[i]))
        # TODO: quantityList not working
        # encrypted_quantity_list.append(encrypt_data(quantity_list[i]))
        encrypted_oid_list.append(encrypt_data(oid_list[i]))
        encrypted_total_price_list.append(encrypt_data(total_price_list[i]))
        encrypted_date_ordered_list.append(encrypt_data(date_ordered_list[i]))
    
    
    
    encrypted_dict = dict(category=encrypted_category_list, brand=encrypted_brand_list, model=encrypted_model_list, price=encrypted_price_list, oid = encrypted_oid_list, total_price = encrypted_total_price_list, date_ordered = encrypted_date_ordered_list )
    print(encrypted_dict)
    return "True"

    # return render_template("cart.html", items=res, numberOfelements=numberOfelements)