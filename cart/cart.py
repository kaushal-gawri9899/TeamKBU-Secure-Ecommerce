"""
Importing the necessary Libraries
"""
from flask import Flask, render_template, redirect, url_for
from flask import Blueprint
from flask.globals import session
import bcrypt
from flask_pymongo import PyMongo
from datetime import date, datetime
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
from InvoiceGenerator.pdf import SimpleInvoice



from tempfile import NamedTemporaryFile

from InvoiceGenerator.api import Invoice, Item, Client, Provider, Creator


os.environ["INVOICE_LANG"] = "en"




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
    open (curr_dir + "/rsa_private.bin"). read (),    passphrase=code
  )
  #Use pkcs1_v1_5 instead of pkcs1_oaep
  #If pkcs1_oaep is used, the data encrypted by jsencrypt.js on the front end cannot be decrypted
  cipher_rsa=PKCS1_v1_5.new (private_key)
  #When decryption fails,Will return sentinel
  ret=cipher_rsa.decrypt (data, "none")
  return ret


def encrypt_data(inputdata, code="123456"):
    data_bytes = inputdata.encode("utf-8")
    private_key=RSA.importKey (
    open (curr_dir + "/rsa_public.pem"). read (),   passphrase=code)
    cipher = PKCS1_v1_5.new(private_key)

    encrypted_bytes = base64.b64encode(cipher.encrypt(data_bytes))

    return encrypted_bytes.decode("utf-8")

    
@cart_bp.route("/addToCart", methods=["POST","GET"])
def addCart():
    try:
        """
        Using Json body
        """

        if not userExists():
            return redirect(url_for('user_bp.login'))

        mytoken = request.values.get("token")
        decryptedToken = str(decrypt_data(mytoken).decode()) + ".appleMango"

        decodedToken = jwt.decode(decryptedToken, options={"verify_signature":False})
        oid = decodedToken['oid']

        token = session['token']
        user_email = returnEmail(token)
  
        data = config.items.find_one({ "_id": ObjectId(oid)})
        category = data["category"]
        brand = data["brand"]
        model = data["model"]
        price =  data["price"]
        quantity = "1"
        product_image = data["product_image"]


        user_id = "kaushalgawri"
        user_name = user_email

        item_data = dict(category=category, brand=brand, model=model, price=price, quantity=quantity, user_id=user_id, user_name=user_name, product_image=product_image)
        config.cart.insert_one(item_data)
        return "True"
        return jsonify(message="Item Added Successfully", flag=True), 201

    except (ex.BadRequestKeyError, KeyError):
        return internal_error()
    
@cart_bp.route("/editCart", methods=["POST"])
# @jwt_required()
def editCart():
    try:
        """
        Using Json body
        """
        if not userExists():
            return redirect(url_for('user_bp.login'))
            
        encryptedToken = request.values.get('token')
        decryptToken = str(decrypt_data(encryptedToken).decode()) + ".mySignature"
        decodedToken = jwt.decode(decryptToken, options={"verify_signature":False})
        oid = decodedToken['OID']
        quantity = decodedToken['quantity']
        data = config.cart.find_one({ "_id": ObjectId(oid)})
        filter = data
        newvalues = { "$set": { 'quantity': int(quantity) } }
        config.cart.update_one(filter, newvalues) 

        return "success"


    except (ex.BadRequestKeyError, KeyError):
        return internal_error()

@cart_bp.route("/deleteCart", methods=["POST"])
# @jwt_required()
def deleteCart():
    try:
        """
        Using Json body
        """
        if not userExists():
            return redirect(url_for('user_bp.login'))

        encryptedToken = request.values.get("token")
        decryptToken = str(decrypt_data(encryptedToken).decode()) + ".mySignature"
        decodedToken = jwt.decode(decryptToken, options={"verify_signature":False})
        oid = decodedToken['oid']
        config.cart.delete_one({ "_id": ObjectId(oid)})
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
    hello = "hello"
    hello = encrypt_data(hello)
    total_price = 0
    for i in range(numberOfelements):
        if res[i]['price']:
            total_price += (int(res[i]['price'])*int(res[i]['quantity']))
    shipCost = 2.99

    wholeCost = total_price+shipCost
  
    decryptedToken = str(decrypt_data(getToken).decode())

    tokenHead = decryptedToken.split(".")
    cost_dict = {"totalCost":wholeCost}

    encodedCost = base64.urlsafe_b64encode(json.dumps(cost_dict).encode()).decode()

    tokenData = tokenHead[0] + "." + encodedCost

    encryptedToken = encrypt_data(tokenData)

    return render_template("cart.html", items=res, numberOfelements=numberOfelements, hello=hello, token=getToken, encryptedToken=encryptedToken)


@cart_bp.route("/payment", methods=["POST"])
def payOrder():
    
    token = request.values.get("token")
    
    decrypted_token = decrypt_data(token).decode()
    signature_token = str(decrypted_token) + ".mySignature"
    decoded_signature_Token = jwt.decode(signature_token, options={"verify_signature":False})
  
    name = decoded_signature_Token["cname"]
    number = decoded_signature_Token["cnum"]
    expiry = decoded_signature_Token["exp"]
    cvv = decoded_signature_Token["cvv"]


    encrypt_name = encrypt_data(name)
    encrypt_num = encrypt_data(number)
    encrypt_exp = encrypt_data(expiry)
    encrypt_cvv = encrypt_data(cvv)




    session_token = session['token']
    user_email = returnEmail(session_token)
    data = config.cart.find({ "user_name": user_email})
    res = json.loads(dumps(data))
  
    numberOfelements = len(res)
   
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

    if  not current_date or not cvv or not name or not number:
        return "Empty Request"

    if validate_date < current_date:
        return "Failure Date"
    if len(cvv) != 3:
        return "Failure cvv"
    if len(number) != 16:
        return "Failure number"
    


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
       

    user_data = dict(category=category_list, brand=brand_list, model=model_list, price=price_list, quantity=quantity_list, cname = encrypt_name, cnum = encrypt_num, cexpiry = encrypt_exp, cvv = encrypt_cvv, user_email = user_email, total_price = total_price, date_ordered = dt_string )

    #Delete last order details
    isExist = config.order.find_one({ "user_email": str(user_email)})

    if isExist:
        config.order.delete_one({"user_email": str(user_email)})
    
    result = config.order.insert_one(user_data)
    if result:
        for i in range(numberOfelements):
            config.cart.delete_one({ "_id": ObjectId(oid_list[i])})
    return "success"


@cart_bp.route("/orders", methods=["POST","GET"])
def getOrderDetails():
    if not userExists():
        return redirect(url_for('user_bp.login'))

    getToken = session['token']
    getEmail = returnEmail(getToken)
    
    data = config.order.find_one({ "user_email": str(getEmail)})
    result = dumps(data)
    res = json.loads(result)
    numberOfelements = len(res)
    
    client_details = "Email : " + getEmail + " Name : " + decrypt_data(res['cname']).decode()
    client = Client(client_details)
    provider = Provider('KPA', bank_account='2600420569', bank_code='2010')
    creator = Creator('KPA')
    
    invoice = Invoice(client, provider, creator)
    invoice.currency_locale = 'en_US'
    invoice.currency = u'$'
        
    if res['_id']['$oid']:
        invoice.number = res['_id']['$oid']
    if res['category']:
        des = ""
        for cat in range(len(res['category'])):
            des = "Category: "+res['category'][cat] + " Brand: "+res['brand'][cat] + " Model: "+ res['model'][cat]
            price = res['price'][cat]
            qt = res['quantity'][cat]
            priceShip = float(res['price'][cat]) + 2.99
            invoice.add_item(Item(count=qt, price=priceShip, description=des))


    pdf = SimpleInvoice(invoice)

    invoice_dir = "static/invoices/" +res['_id']['$oid']+'.pdf' 


    pdf.gen(invoice_dir, generate_qr_code=True)
    

    tokenDecrypt = str(decrypt_data(getToken).decode())

    tokenHead = tokenDecrypt.split(".")

    
    invoice_dict = {"invoiceDict" : invoice_dir}

    encodedDir = base64.urlsafe_b64encode(json.dumps(invoice_dict).encode()).decode()
    newTokenDir = tokenHead[0] + "." + encodedDir

    encrypted_Dir = encrypt_data(newTokenDir)
    session['invoice'] = encrypted_Dir

    return render_template("paymentSuccess.html")
