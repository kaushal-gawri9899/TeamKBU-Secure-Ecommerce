"""
Importing the necessary Libraries
"""
from flask import Flask
import base64
from flask import Blueprint
import bcrypt
import pymongo.errors
from flask_pymongo import PyMongo
from Crypto.PublicKey import RSA
import rsa
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
from base64 import b64decode

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
            #print(request.args.get)
            print(request.form)
            
            user_email = request.form["email"]
            user_password = request.form["password"]
            #user_token = request.form["token"]
           #alue = request.form["token"]
            #token = request.get_json()
            #print("Here")
            #print(value)
            #print(value)
            # print(user_token)
            #rsa_key = "---BEGIN PRIVATE KEY-----MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDN3Fp6Lpu3/EgCFix0V1brYIZOlFf4ZehmTOq9t/mg7HDjAoQ2MVfsuyplfF0V+hHETAf3TNkcseCw0XNd7cmqJFpsgNw1mYpLYXQDv4zCvHorZ9nlvsTZ9IsVsLsWy8vbaY3Qo0Cnfm10AOmXiUqo0W4Xs1PbZkGn9fedyh3xwO8xv22XSGJDWEm/QfwzL/fXD4X4J1q3/0lrl3XO045gjHWZnYUPabYzff8GAZj8G6xQqpKT1b3USH3360dLmhO8TwIjyDum+FC16qZWAFsk5rvd5CFl85AnRpZDmbaLQ1Q9ybC8YPNRFdMpb7vZQoPPrvVsTtgByHYf5TtRB5rDAgMBAAECggEAUDPieCnCd1rtvwpehXElpwxzJxg6ccdaVMjwx7tuoRidHoRzeB2fUNbWvLVIGvDTjTPGAr5I9BoFHT5tARJMeGIzbISDxsosDBRKu88cCx6dRl3ukcjSLsxMh8XUDhyWLsSgAMIpxVfHUuOsHmLZ2I3Ho6o1KIxdVg/JSgtdwTqjz3w8jmGQ/NXgc7Ym/ys1fLG9L2nYdMzK/mRJf/BnXiCNE6/SYlZYO716oC688UJBWS3BqB9jaJyNpigX//ynJvU6xw8FhHt4fRStUmCCYAYhCQu3XgbtmxKisDGhdBVASG+DM+vVTh+sSvxkNrjJjF+m2tSg578A8C8Ls0r3uQKBgQDpO9e178NR0HHmvWbZR9+uPugf4UT9+U2/dEfJBHAOp2GRsIvXkFwbPHuSHkc0iEPwz+U8gPC8jInSslKOUDtaGtUaVzzWrxxh7DggWx4pYs3I0Ki8C+CRTTdOY9GAFa9jhIyRmf6v9QoAH/loGNV2qYFbb+HweD0PnxlWha1txQKBgQDh9IBBltW7T96foUmHOn+x6xlF5MNDHxLBY6bngxKvMTZoi5C6wmmCmasF45LWbkvUiMAsovYN5z4cJnKXWmRmCS8NXUucmUgdvsmCbiB62BmZvHaOffmnIdhcAjBebT/Bn5qMvKCNy3fQFSfuEw1eRRO2IofB4o7z7m794vo25wKBgEPowrQcrZhCwwdWGn4laUGI23l80+PHFRYru0MSYbZCkiwjZXRMeiUMBUbUPhNTocSaI7rsKCweF3sbpOH/BmkD6wySXgp8Th1M9EKnhS6zsAtKhfbK1oY4H2RZuAQ9TCYD0BIM7pU5GcJTjQD8ShsU269N8lFcERtdTbldjtOpAoGAF4YkADAa6lhjXg0loY2Gk9hdFji913QZuMaOLtYnkNO3zWSSWc85ut4Svxc1R1vOSz89eqgwo7vqbHXYQken4jOckXCgGZqftnERe6HJgeCTsby8PxOAdVUBuHqF3J7VH2xlY7eTo4+GVsSNFq0nHCRm6/RmW9ohdeXh6k7CLAsCgYBZe3RLWuffKxg+lZmv9tJDOO813QPLFeixrBYhKjGDcwjVYcCugGNDmyStM0/++uWddgMKavNALjpamu8KolDNivrjL1qaFHX9Bpi108T+dDn2WpX+vUP6hjA/U2wtTvUbJle1SsbZxRrV9gf5PAJqTrQY4u28ezjR3PCV+R4kdw==-----END PRIVATE KEY-----"
            encrypted = str(request.form["encrypted"])
            decrypted = str(request.form["decrypted"])
            print(decrypted)
            
           
            rsa_key = """-----BEGIN RSA PRIVATE KEY-----
                        MIIEowIBAAKCAQB7X1cyesSJ8ddILamicBhkjNMOjffLHK+zfEIIL06Kg1sy4bJR
Mv99tLv9V00KJM2iIitrD4yQxgxcYBUgZxWlt5qMVs2v5doCV4PVrL3wBMV1Ys7C
pZ5QhyWNrtKXMTVSbVDhRIPvhwLqdR3HAVX/v3ESeoOE3ekx7d2W7I0FiV/xXm7k
BRz92/NQLX6qrNQQj/RAn4J/5+apKqXnHkMxtwtQV67lZhrVNjenKTWC2YKcldRG
gqHopw8UltlKtMfWXmU20/hFraDDhH2BaLyLp1ZiqZnsm6IXRyOIiPWUNFTpOSqW
zBor7ZD89cCT8v9ahlZi6ZpeH96Zsz7fw/FtAgMBAAECggEAacAfjjWNonCaiFQb
xBEx136eqysl7AR61u776ugh+rj9w2+S2edM+QOi4FWkw70oRoHjlbGOW8pnbgcu
FMhH1fS7lPAS/2OWq8s4Rj/7z3FHkIdRk6dDPOObXQctnEuh2TW6zl1cekTQSwh4
rcyHWuFOmvhJI+rTqOiruGKrvsH2cKfGfS9QvKNscdeU4dOsbKSViL5ztSoHfQKV
jgMXqVZ1RXHoo9zjtunXONeDA0N9eVjCRjbd5eDy9VPmMba/x2YChevwesSp5RO3
8XCiMFR35lDzdAjy1ELD2uphyUYxyOZc+kcNYrqzZgsSkZZvuQzhNFLe714gSy28
8D2CAQKBgQDpL0jaePRyZA2QR38WSJBuZ2JN1kwwc7hlJd9BO65jKfX5+9C6dDDj
fPbSAzfLMVtMKyJ0n5Ht0E2rj0YDCv0v196IHrV2QUvhpa/zSagvKxg6RB+bu1fR
r5QAXd3q1J+v8hatRd7cscjRj4oX5DCmshuxntMuvOOVkIV3Zjaf9QKBgQCHcYXV
lJl2RGfBgY3I4MvDNSsD5yK0BvIzY+VNaFEnEIMrmQiH/kVLq5lhi4XQRoa9fmai
OhyBggGiIAHkS7BeU+2NtbFTr7Sg0B13me2GAi2o3dMCCL3Edb8hkrlZHSpb1klT
Y0hY68d2lU+xmOVpbiyMHZtmcVg2eS7oqOX4mQKBgQCIaZwCCs5d+QAiTmEfZRXx
MFPG2z24/ol5ypz/aW2MH2kBc/nYic5r1pgBpdZG7TnOplFCznKtH7XATlGTyCLz
kSJimSxo4KwGdkonVgioh1pmA6JGFWO7jC5VxJPlI7vDTylK9lv42Zx0U7diYKDB
c+JVl2dNqTyuK1yYy9fa3QKBgG1xUc+PT6G9DInUAZl766pE4Ak7T1Ng+XyFD9hI
nqqOMS+dbMNWtu+6LSog73OoSV/9LzmO81HCl0dFzcGHV3AhKScE1dDlfXMkN2tZ
OhC62eJFvCc8oPqKmnKqeJKFeqDSulVjOCaB/p7Xb5n2DgnvOJfPpK5WkA0URs9B
CvKhAoGBAKhnDozKllg9CW4fL+ciTbkvdlD/PU2QgDf4YRKM/lZZPTX4kO0yQGM4
bepwezi6vHwOIyz9bU5dx77a8Cepk+Xnf1izRYJjfVC0lkWpsOpdw9DhCXQiVA3I
Hv6IaPh/6MUgYHwEbzdGzDQY2qLJ7tCuZ4Za2bsTWnLMIL/vwn18
-----END RSA PRIVATE KEY-----"""

            output = []

            ciphertext = base64.b64decode(encrypted)
            key = RSA.importKey(rsa_key)
            cipher = PKCS1_v1_5.new(key)
          
            message = cipher.decrypt(ciphertext, Random.new().read(256))
      
            print(base64.b64encode((message)).decode("utf-8"))
            
           
            # for i in message:
            #     print(i)
            #     output.append(i.decode("utf-8", "slashescape"))

            # # d = bytearray(message, )
            # # d = bytearray.fromhex(message).decode()
            # # print(d)
            # print(output)
            # msg = "Hi"
            # dsize = SHA.digest_size
            # sentinel = Random.new().read(15+dsize) 
            # # decoded_data = base64.b64decode(encrypted.encode())
            # keyDER = base64.b64decode(rsa_key)
            # keyPub = RSA.importKey(keyDER)
            # print(keyPub)
            # decrypter = PKCS1_v1_5.new(keyPub)
            # c = decrypter.encrypt(msg)
            # c2 = base64.b64encode(c)
            # print("Encrypt", c2)
            
            # sentinel = Random.new().read(256)
            # decrypted = decrypter.decrypt(encrypted.encode(), sentinel)

            # print(decrypted)

            # keyDER = b64decode(rsa_key)
            # keyPub = RSA.importKey(keyDER)

            # cipher = PKCS1_OAEP.new(keyPub)
            # # print('KeyPub: ', keyPub)
            # # print("\n Cipher: ",cipher)
            # # print(len(encrypted.encode()))

            # curr_len = len(encrypted)
            # def_len = 256
            # encrypted_byte = message

            # # print("Encrypted byte: ", encrypted_byte)

            # if curr_len < def_len:
            #     decrypt_val = cipher.decrypt(encrypted_byte, 256)
            # else:
            #     offset = 0
            #     res = []
            #     while curr_len - offset > 0:
            #         if curr_len-offset > def_len:
            #             print(encrypted_byte[offset: offset+def_len])
            #             res.append(cipher.decrypt(encrypted_byte[offset: offset + def_len], 256))
            #         else:
            #             res.append(cipher.decrypt(encrypted_byte[offset:], 256))
                    
            #         offset +=def_len
            #     decrypt_val = b''.join(res)
            # decrypted = decrypt_val.decode()


            # #cipher_text = cipher.decrypt(encrypted.encode())

            # print(decrypted)



            current_user = config.zhiffy.find_one({'email': user_email})
        
            if user_email and user_password:
                if current_user:
                    if bcrypt.hashpw(user_password.encode('utf-8'), current_user["password"]) == current_user["password"]:
                        user_access_token = create_access_token(identity=user_email)
                        print(user_access_token)
                        return redirect(url_for('product_bp.getAllItems', token=user_access_token))
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





