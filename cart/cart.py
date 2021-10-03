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
  #sentinel=none
  
  ret=cipher_rsa.decrypt (data, "none")
  return ret

# def encrypt_data(inputdata, code="123456"):
#     data = base64.b64encode(bytes(inputdata.encode()))
#     print("Data would be", data)

#     #print("Old data", base64.b64decode(data))
# #     private_key=RSA.importKey (
# #     open (curr_dir + "/my_private_rsa_key.bin"). read (),    passphrase=code
# #   )
#     private_key=RSA.importKey (
#     open (curr_dir + "/my_rsa_public.pem"). read (),    passphrase=code
#     )
#     cipher_rsa=PKCS1_v1_5.new (private_key)
#     ret = cipher_rsa.encrypt(data)
#     return ret

def encrypt_data(inputdata, code="123456"):
    data_bytes = inputdata.encode("utf-8")
    # private_key=RSA.importKey (
    # open (curr_dir + "/my_private_rsa_key.bin"). read (),   passphrase=code)
    private_key=RSA.importKey (
    open (curr_dir + "/rsa_public.pem"). read (),   passphrase=code)

    # pri_key = "-----BEGIN RSA PRIVATE KEY-----MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDN3Fp6Lpu3/EgCFix0V1brYIZOlFf4ZehmTOq9t/mg7HDjAoQ2MVfsuyplfF0V+hHETAf3TNkcseCw0XNd7cmqJFpsgNw1mYpLYXQDv4zCvHorZ9nlvsTZ9IsVsLsWy8vbaY3Qo0Cnfm10AOmXiUqo0W4Xs1PbZkGn9fedyh3xwO8xv22XSGJDWEm/QfwzL/fXD4X4J1q3/0lrl3XO045gjHWZnYUPabYzff8GAZj8G6xQqpKT1b3USH3360dLmhO8TwIjyDum+FC16qZWAFsk5rvd5CFl85AnRpZDmbaLQ1Q9ybC8YPNRFdMpb7vZQoPPrvVsTtgByHYf5TtRB5rDAgMBAAECggEAUDPieCnCd1rtvwpehXElpwxzJxg6ccdaVMjwx7tuoRidHoRzeB2fUNbWvLVIGvDTjTPGAr5I9BoFHT5tARJMeGIzbISDxsosDBRKu88cCx6dRl3ukcjSLsxMh8XUDhyWLsSgAMIpxVfHUuOsHmLZ2I3Ho6o1KIxdVg/JSgtdwTqjz3w8jmGQ/NXgc7Ym/ys1fLG9L2nYdMzK/mRJf/BnXiCNE6/SYlZYO716oC688UJBWS3BqB9jaJyNpigX//ynJvU6xw8FhHt4fRStUmCCYAYhCQu3XgbtmxKisDGhdBVASG+DM+vVTh+sSvxkNrjJjF+m2tSg578A8C8Ls0r3uQKBgQDpO9e178NR0HHmvWbZR9+uPugf4UT9+U2/dEfJBHAOp2GRsIvXkFwbPHuSHkc0iEPwz+U8gPC8jInSslKOUDtaGtUaVzzWrxxh7DggWx4pYs3I0Ki8C+CRTTdOY9GAFa9jhIyRmf6v9QoAH/loGNV2qYFbb+HweD0PnxlWha1txQKBgQDh9IBBltW7T96foUmHOn+x6xlF5MNDHxLBY6bngxKvMTZoi5C6wmmCmasF45LWbkvUiMAsovYN5z4cJnKXWmRmCS8NXUucmUgdvsmCbiB62BmZvHaOffmnIdhcAjBebT/Bn5qMvKCNy3fQFSfuEw1eRRO2IofB4o7z7m794vo25wKBgEPowrQcrZhCwwdWGn4laUGI23l80+PHFRYru0MSYbZCkiwjZXRMeiUMBUbUPhNTocSaI7rsKCweF3sbpOH/BmkD6wySXgp8Th1M9EKnhS6zsAtKhfbK1oY4H2RZuAQ9TCYD0BIM7pU5GcJTjQD8ShsU269N8lFcERtdTbldjtOpAoGAF4YkADAa6lhjXg0loY2Gk9hdFji913QZuMaOLtYnkNO3zWSSWc85ut4Svxc1R1vOSz89eqgwo7vqbHXYQken4jOckXCgGZqftnERe6HJgeCTsby8PxOAdVUBuHqF3J7VH2xlY7eTo4+GVsSNFq0nHCRm6/RmW9ohdeXh6k7CLAsCgYBZe3RLWuffKxg+lZmv9tJDOO813QPLFeixrBYhKjGDcwjVYcCugGNDmyStM0/++uWddgMKavNALjpamu8KolDNivrjL1qaFHX9Bpi108T+dDn2WpX+vUP6hjA/U2wtTvUbJle1SsbZxRrV9gf5PAJqTrQY4u28ezjR3PCV+R4kdw==-----END RSA PRIVATE KEY-----"
   
    # private_key = RSA.importKey(pri_key)
    # private_key=RSA.importKey (
    # open (curr_dir + "/my_rsa_public.pem"). read (),    passphrase=code
    # )

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
        print("OID", mytoken)
        decryptedToken = str(decrypt_data(mytoken).decode()) + ".appleMango"
        print(decryptedToken)
        print("scucces")
        decodedToken = jwt.decode(decryptedToken, options={"verify_signature":False})
        oid = decodedToken['oid']
        print(oid)

        token = session['token']
        # myToken = decrypt_data(token)
        # print(myToken)
        # print("here")
        user_email = returnEmail(token)
        print("check")
        print(user_email)
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
        # a = {"success":"b"}
        # b = json.dumps(a)
        # return b
        # return "success"
        # return redirect(url_for('cart_bp.getCartDetails'))
        
        # return jsonify(message="Item Added Successfully", flag=True), 201
        #return redirect(url_for('cart_bp.getCartDetails'))
        return "True"
        return jsonify(message="Item Added Successfully", flag=True), 201

    except (ex.BadRequestKeyError, KeyError):
        print("Hello")
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
        print(oid)

        # return redirect(url_for('cart_bp.getCartDetails'))

        config.cart.delete_one({ "_id": ObjectId(oid)})
        print("success")
        # return "success"
        # oid = request.values.get("oid")
        # print(oid, "I WAS CALLED")
        # newOid = decrypt_data(oid)
        # config.cart.delete_one({ "_id": ObjectId(newOid.decode())})

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
    hello = "hello"
    hello = encrypt_data(hello)
    total_price = 0
    for i in range(numberOfelements):
        if res[i]['price']:
            total_price += int(res[i]['price'])
    print(total_price)
    shipCost = 2.99

    wholeCost = total_price+shipCost
    # print(str(decrypt_data(session['token']).decode()).split('.'), "HELLELELELELELEL")
  
    decryptedToken = str(decrypt_data(getToken).decode())

    tokenHead = decryptedToken.split(".")
    print(tokenHead[0])

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
    # decryptToken = str(decrypt_data(encryptedToken).decode()) + ".mySignature"
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
    # TODO: Error mesaage as date is bad
    print(validate_date)
    print(current_date)

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
       

    user_data = dict(category=category_list, brand=brand_list, model=model_list, price=price_list, quantity=quantity_list, cname = name, cnum = number, cexpiry = expiry, cvv = cvv, user_email = user_email, total_price = total_price, date_ordered = dt_string )
    # print(category_list, brand_list, model_list, price_list, quantity_list)
    #Delete last order details
    isExist = config.order.find_one({ "user_email": str(user_email)})

    if isExist:
        config.order.delete_one({"user_email": str(user_email)})
    
    result = config.order.insert_one(user_data)
    if result:
        print(result)
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
    
    print(res)

    


    print(getEmail)
    
    client_details = "Email : " + getEmail + " Name : " + res['cname']
    client = Client(client_details)
    provider = Provider('KPA', bank_account='2600420569', bank_code='2010')
    creator = Creator('KPA')
    
    invoice = Invoice(client, provider, creator)
    invoice.currency_locale = 'en_US'
    invoice.currency = u'$'
    # invoice.add_item(Item(32, 600, description="Item 1"))
    # invoice.add_item(Item(60, 50, description="Item 2", tax=21))
    # invoice.add_item(Item(50, 60, description="Item 3", tax=0))
    # invoice.add_item(Item(5, 600, description="Item 4", tax=15))




    
    # return "None"

    # category_list = []
    # brand_list = []
    # model_list = []
    # price_list = []
    # quantity_list = []
    # oid_list = []
    # total_price_list = []
    # date_ordered_list = []

    #invoice = Invoice(client, provider, creator)
    # for i in range(numberOfelements):
    print("ID", res['_id']['$oid'])
        
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

    #encrypted_invoice_dir = encrypt_data(invoice_dir)

    #session['invoice'] = encrypted_invoice_dir


    pdf.gen(invoice_dir, generate_qr_code=True)
    

    tokenDecrypt = str(decrypt_data(getToken).decode())
    print(tokenDecrypt)

    tokenHead = tokenDecrypt.split(".")
    print(tokenHead[0])

    
    
    invoice_dict = {"invoiceDict" : invoice_dir}

    encodedDir = base64.urlsafe_b64encode(json.dumps(invoice_dict).encode()).decode()
    newTokenDir = tokenHead[0] + "." + encodedDir

    encrypted_Dir = encrypt_data(newTokenDir)
    session['invoice'] = encrypted_Dir
    print("DIR", encrypted_Dir)


    # for i in range(numberOfelements):
    #     # if res[i]['_id']['$oid']:
    #     #     oid_list.append(res[i]['_id']['$oid'])
    #     # if res[i]['total_price']:
    #     #     val = str(res[i]['total_price'])
    #     #     # if len(val) % 4:
    #     #     #     # not a multiple of 4, add padding:
    #     #     #     val += '=' * (4 - len(val) % 4) 
    #     #     total_price_list.append(val)
    #     # if res[i]['date_ordered']:
    #     #     date_ordered_list.append(res[i]['date_ordered'])
    #     if res[i]['category'][0]:
    #         # if len(res[i]['category'][0]) % 4:
    #         #     # not a multiple of 4, add padding:
    #         #     res[i]['category'][0] += '=' * (4 - len(res[i]['category'][0]) % 4) 
    #         category_list.append(res[i]['category'][0])
    #     if res[i]['brand'][0]:
    #         # if len(res[i]['brand'][0]) % 4:
    #         #     # not a multiple of 4, add padding:
    #         #     res[i]['brand'][0] += '=' * (4 - len(res[i]['brand'][0]) % 4) 
    #         brand_list.append(res[i]['brand'][0])
    #     if res[i]['model'][0]:
    #         # if len(res[i]['model'][0]) % 4:
    #         #     # not a multiple of 4, add padding:
    #         #     res[i]['model'][0] += '=' * (4 - len(res[i]['model'][0]) % 4) 
    #         model_list.append(res[i]['model'][0])
    #     if res[i]['price'][0]:
    #         # if len(str(res[i]['price'][0])) % 4:
    #         #     # not a multiple of 4, add padding:
    #         #     res[i]['price'][0] += '=' * (4 - len(str(res[i]['price'][0])) % 4) 
    #         price_list.append(str(res[i]['price'][0]))
    #     if res[i]['quantity'][0]:
    #         val = str(res[i]['quantity'][0])
    #         # if len(val) % 4:
    #         #     # not a multiple of 4, add padding:
    #         #     val += '=' * (4 - len(val) % 4) 
    #         quantity_list.append(val)
   
    # encrypted_category_list = []
    # encrypted_brand_list = []
    # encrypted_model_list = []
    # encrypted_price_list = []
    # encrypted_quantity_list = []
    # encrypted_oid_list = []
    # encrypted_total_price_list = []
    # encrypted_date_ordered_list = []

    # for i in range(numberOfelements):
    #     print(i)
        # encrypted_category_list.append(encrypt_data(category_list[i]))
        # encrypted_brand_list.append(encrypt_data(brand_list[i]))
        # encrypted_model_list.append(encrypt_data(model_list[i]))
        # encrypted_price_list.append(encrypt_data(price_list[i]))
        # # TODO: quantityList not working
        # # encrypted_quantity_list.append(encrypt_data(quantity_list[i]))
        # encrypted_oid_list.append(encrypt_data(oid_list[i]))
        # encrypted_total_price_list.append(encrypt_data(total_price_list[i]))
        # encrypted_date_ordered_list.append(encrypt_data(date_ordered_list[i]))
    
    
    # print(category_list)
    # encrypted_dict = dict(category=category_list, brand=brand_list, model=model_list, price=price_list, oid = oid_list, total_price = total_price_list, date_ordered = date_ordered_list )
    # print(encrypted_dict)
   # return render_template("orders.html", dict=res)
    return render_template("paymentSuccess.html")

    # return render_template("cart.html", items=res, numberOfelements=numberOfelements)