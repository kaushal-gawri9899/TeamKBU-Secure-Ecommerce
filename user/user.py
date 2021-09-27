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
            # _json = request.json
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
            encrypted = request.form["encrypted"]
            # cipher = bytes(encrypted, 'raw_unicode_escape')
            # #print(str(encrypted))
            # # decode = base64.b64decode(encrypted)
            # # cipher = PKCS1_OAEP.new(rsa_key)
            # # decrypted = cipher.decrypt(decode)
            # # print(decrypted)

            # base64text = base64.b64encode(cipher).decode()
            # print(base64text)
            # cipher = PKCS1_OAEP.new(rsa_key)
            # decrypted = cipher.decrypt(base64text)
            # text = rsa.decrypt(base64.b64decode(base64text.encode()), rsa_key)

            # print("TEXT  \n", text)

            # key = "---BEGIN RSA PRIVATE KEY-----MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDN3Fp6Lpu3/EgCFix0V1brYIZOlFf4ZehmTOq9t/mg7HDjAoQ2MVfsuyplfF0V+hHETAf3TNkcseCw0XNd7cmqJFpsgNw1mYpLYXQDv4zCvHorZ9nlvsTZ9IsVsLsWy8vbaY3Qo0Cnfm10AOmXiUqo0W4Xs1PbZkGn9fedyh3xwO8xv22XSGJDWEm/QfwzL/fXD4X4J1q3/0lrl3XO045gjHWZnYUPabYzff8GAZj8G6xQqpKT1b3USH3360dLmhO8TwIjyDum+FC16qZWAFsk5rvd5CFl85AnRpZDmbaLQ1Q9ybC8YPNRFdMpb7vZQoPPrvVsTtgByHYf5TtRB5rDAgMBAAECggEAUDPieCnCd1rtvwpehXElpwxzJxg6ccdaVMjwx7tuoRidHoRzeB2fUNbWvLVIGvDTjTPGAr5I9BoFHT5tARJMeGIzbISDxsosDBRKu88cCx6dRl3ukcjSLsxMh8XUDhyWLsSgAMIpxVfHUuOsHmLZ2I3Ho6o1KIxdVg/JSgtdwTqjz3w8jmGQ/NXgc7Ym/ys1fLG9L2nYdMzK/mRJf/BnXiCNE6/SYlZYO716oC688UJBWS3BqB9jaJyNpigX//ynJvU6xw8FhHt4fRStUmCCYAYhCQu3XgbtmxKisDGhdBVASG+DM+vVTh+sSvxkNrjJjF+m2tSg578A8C8Ls0r3uQKBgQDpO9e178NR0HHmvWbZR9+uPugf4UT9+U2/dEfJBHAOp2GRsIvXkFwbPHuSHkc0iEPwz+U8gPC8jInSslKOUDtaGtUaVzzWrxxh7DggWx4pYs3I0Ki8C+CRTTdOY9GAFa9jhIyRmf6v9QoAH/loGNV2qYFbb+HweD0PnxlWha1txQKBgQDh9IBBltW7T96foUmHOn+x6xlF5MNDHxLBY6bngxKvMTZoi5C6wmmCmasF45LWbkvUiMAsovYN5z4cJnKXWmRmCS8NXUucmUgdvsmCbiB62BmZvHaOffmnIdhcAjBebT/Bn5qMvKCNy3fQFSfuEw1eRRO2IofB4o7z7m794vo25wKBgEPowrQcrZhCwwdWGn4laUGI23l80+PHFRYru0MSYbZCkiwjZXRMeiUMBUbUPhNTocSaI7rsKCweF3sbpOH/BmkD6wySXgp8Th1M9EKnhS6zsAtKhfbK1oY4H2RZuAQ9TCYD0BIM7pU5GcJTjQD8ShsU269N8lFcERtdTbldjtOpAoGAF4YkADAa6lhjXg0loY2Gk9hdFji913QZuMaOLtYnkNO3zWSSWc85ut4Svxc1R1vOSz89eqgwo7vqbHXYQken4jOckXCgGZqftnERe6HJgeCTsby8PxOAdVUBuHqF3J7VH2xlY7eTo4+GVsSNFq0nHCRm6/RmW9ohdeXh6k7CLAsCgYBZe3RLWuffKxg+lZmv9tJDOO813QPLFeixrBYhKjGDcwjVYcCugGNDmyStM0/++uWddgMKavNALjpamu8KolDNivrjL1qaFHX9Bpi108T+dDn2WpX+vUP6hjA/U2wtTvUbJle1SsbZxRrV9gf5PAJqTrQY4u28ezjR3PCV+R4kdw==-----END RSA PRIVATE KEY-----"
            # #print(RSA.generate(4096))
            # print(type(RSA.generate(1024)))
            # f = open('keyfile.pem', 'wb')
            # f.write(key.exportKey('PEM'))
            # f.close()
            
            # f = open('keyfile.pem', 'rb')

            # rsa_key = RSA.importKey(f.read())
            
            # cipher = PKCS1_v1_5.new(rsa_key)
            # raw_cipher_data = b64decode(encrypted)
            # phn = cipher.decrypt(raw_cipher_data)


            
            # print(phn)

            # keyPair = RSA.generate(1024)

            # pubKey = keyPair.publickey()
            # print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
            # pubKeyPEM = pubKey.exportKey()
            # print(pubKeyPEM.decode('ascii'))

            # print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
            # privKeyPEM = keyPair.exportKey()
            # print(privKeyPEM.decode('ascii'))

            # key = RSA.importKey(open('D:/SecureEcommProject/Secure-E-comm-register_login/user/private.pem').read())
            # cipher = PKCS1_OAEP.new(key)
            # message = cipher.decrypt(encrypted)

            #rsa_key = '----BEGIN PRIVATE KEY-----MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDN3Fp6Lpu3/EgCFix0V1brYIZOlFf4ZehmTOq9t/mg7HDjAoQ2MVfsuyplfF0V+hHETAf3TNkcseCw0XNd7cmqJFpsgNw1mYpLYXQDv4zCvHorZ9nlvsTZ9IsVsLsWy8vbaY3Qo0Cnfm10AOmXiUqo0W4Xs1PbZkGn9fedyh3xwO8xv22XSGJDWEm/QfwzL/fXD4X4J1q3/0lrl3XO045gjHWZnYUPabYzff8GAZj8G6xQqpKT1b3USH3360dLmhO8TwIjyDum+FC16qZWAFsk5rvd5CFl85AnRpZDmbaLQ1Q9ybC8YPNRFdMpb7vZQoPPrvVsTtgByHYf5TtRB5rDAgMBAAECggEAUDPieCnCd1rtvwpehXElpwxzJxg6ccdaVMjwx7tuoRidHoRzeB2fUNbWvLVIGvDTjTPGAr5I9BoFHT5tARJMeGIzbISDxsosDBRKu88cCx6dRl3ukcjSLsxMh8XUDhyWLsSgAMIpxVfHUuOsHmLZ2I3Ho6o1KIxdVg/JSgtdwTqjz3w8jmGQ/NXgc7Ym/ys1fLG9L2nYdMzK/mRJf/BnXiCNE6/SYlZYO716oC688UJBWS3BqB9jaJyNpigX//ynJvU6xw8FhHt4fRStUmCCYAYhCQu3XgbtmxKisDGhdBVASG+DM+vVTh+sSvxkNrjJjF+m2tSg578A8C8Ls0r3uQKBgQDpO9e178NR0HHmvWbZR9+uPugf4UT9+U2/dEfJBHAOp2GRsIvXkFwbPHuSHkc0iEPwz+U8gPC8jInSslKOUDtaGtUaVzzWrxxh7DggWx4pYs3I0Ki8C+CRTTdOY9GAFa9jhIyRmf6v9QoAH/loGNV2qYFbb+HweD0PnxlWha1txQKBgQDh9IBBltW7T96foUmHOn+x6xlF5MNDHxLBY6bngxKvMTZoi5C6wmmCmasF45LWbkvUiMAsovYN5z4cJnKXWmRmCS8NXUucmUgdvsmCbiB62BmZvHaOffmnIdhcAjBebT/Bn5qMvKCNy3fQFSfuEw1eRRO2IofB4o7z7m794vo25wKBgEPowrQcrZhCwwdWGn4laUGI23l80+PHFRYru0MSYbZCkiwjZXRMeiUMBUbUPhNTocSaI7rsKCweF3sbpOH/BmkD6wySXgp8Th1M9EKnhS6zsAtKhfbK1oY4H2RZuAQ9TCYD0BIM7pU5GcJTjQD8ShsU269N8lFcERtdTbldjtOpAoGAF4YkADAa6lhjXg0loY2Gk9hdFji913QZuMaOLtYnkNO3zWSSWc85ut4Svxc1R1vOSz89eqgwo7vqbHXYQken4jOckXCgGZqftnERe6HJgeCTsby8PxOAdVUBuHqF3J7VH2xlY7eTo4+GVsSNFq0nHCRm6/RmW9ohdeXh6k7CLAsCgYBZe3RLWuffKxg+lZmv9tJDOO813QPLFeixrBYhKjGDcwjVYcCugGNDmyStM0/++uWddgMKavNALjpamu8KolDNivrjL1qaFHX9Bpi108T+dDn2WpX+vUP6hjA/U2wtTvUbJle1SsbZxRrV9gf5PAJqTrQY4u28ezjR3PCV+R4kdw==-----END PRIVATE KEY-----'

            rsa_key = 'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDN3Fp6Lpu3/EgCFix0V1brYIZOlFf4ZehmTOq9t/mg7HDjAoQ2MVfsuyplfF0V+hHETAf3TNkcseCw0XNd7cmqJFpsgNw1mYpLYXQDv4zCvHorZ9nlvsTZ9IsVsLsWy8vbaY3Qo0Cnfm10AOmXiUqo0W4Xs1PbZkGn9fedyh3xwO8xv22XSGJDWEm/QfwzL/fXD4X4J1q3/0lrl3XO045gjHWZnYUPabYzff8GAZj8G6xQqpKT1b3USH3360dLmhO8TwIjyDum+FC16qZWAFsk5rvd5CFl85AnRpZDmbaLQ1Q9ybC8YPNRFdMpb7vZQoPPrvVsTtgByHYf5TtRB5rDAgMBAAECggEAUDPieCnCd1rtvwpehXElpwxzJxg6ccdaVMjwx7tuoRidHoRzeB2fUNbWvLVIGvDTjTPGAr5I9BoFHT5tARJMeGIzbISDxsosDBRKu88cCx6dRl3ukcjSLsxMh8XUDhyWLsSgAMIpxVfHUuOsHmLZ2I3Ho6o1KIxdVg/JSgtdwTqjz3w8jmGQ/NXgc7Ym/ys1fLG9L2nYdMzK/mRJf/BnXiCNE6/SYlZYO716oC688UJBWS3BqB9jaJyNpigX//ynJvU6xw8FhHt4fRStUmCCYAYhCQu3XgbtmxKisDGhdBVASG+DM+vVTh+sSvxkNrjJjF+m2tSg578A8C8Ls0r3uQKBgQDpO9e178NR0HHmvWbZR9+uPugf4UT9+U2/dEfJBHAOp2GRsIvXkFwbPHuSHkc0iEPwz+U8gPC8jInSslKOUDtaGtUaVzzWrxxh7DggWx4pYs3I0Ki8C+CRTTdOY9GAFa9jhIyRmf6v9QoAH/loGNV2qYFbb+HweD0PnxlWha1txQKBgQDh9IBBltW7T96foUmHOn+x6xlF5MNDHxLBY6bngxKvMTZoi5C6wmmCmasF45LWbkvUiMAsovYN5z4cJnKXWmRmCS8NXUucmUgdvsmCbiB62BmZvHaOffmnIdhcAjBebT/Bn5qMvKCNy3fQFSfuEw1eRRO2IofB4o7z7m794vo25wKBgEPowrQcrZhCwwdWGn4laUGI23l80+PHFRYru0MSYbZCkiwjZXRMeiUMBUbUPhNTocSaI7rsKCweF3sbpOH/BmkD6wySXgp8Th1M9EKnhS6zsAtKhfbK1oY4H2RZuAQ9TCYD0BIM7pU5GcJTjQD8ShsU269N8lFcERtdTbldjtOpAoGAF4YkADAa6lhjXg0loY2Gk9hdFji913QZuMaOLtYnkNO3zWSSWc85ut4Svxc1R1vOSz89eqgwo7vqbHXYQken4jOckXCgGZqftnERe6HJgeCTsby8PxOAdVUBuHqF3J7VH2xlY7eTo4+GVsSNFq0nHCRm6/RmW9ohdeXh6k7CLAsCgYBZe3RLWuffKxg+lZmv9tJDOO813QPLFeixrBYhKjGDcwjVYcCugGNDmyStM0/++uWddgMKavNALjpamu8KolDNivrjL1qaFHX9Bpi108T+dDn2WpX+vUP6hjA/U2wtTvUbJle1SsbZxRrV9gf5PAJqTrQY4u28ezjR3PCV+R4kdw=='

            decoded_data = base64.b64decode(encrypted.encode())
            keyDER = b64decode(rsa_key)
            keyPub = RSA.importKey(keyDER)
            decrypter = PKCS1_v1_5.new(keyPub)
            sentinel = Random.new().read(256)
            decrypted = decrypter.decrypt(encrypted.encode(), sentinel)

            print(decrypted)

            # keyDER = b64decode(rsa_key)
            # keyPub = RSA.importKey(keyDER)

            # cipher = PKCS1_OAEP.new(keyPub)
            # # print('KeyPub: ', keyPub)
            # # print("\n Cipher: ",cipher)
            # # print(len(encrypted.encode()))

            # curr_len = len(encrypted)
            # def_len = 128
            # encrypted_byte = base64.b64decode(encrypted.encode())

            # # print("Encrypted byte: ", encrypted_byte)

            # if curr_len < def_len:
            #     decrypt_val = decrypter.decrypt(encrypted_byte, 'failure')
            # else:
            #     offset = 0
            #     res = []
            #     while curr_len - offset > 0:
            #         if curr_len-offset > def_len:
            #             print(encrypted_byte[offset: offset+def_len])
            #             res.append(decrypter.decrypt(encrypted_byte[offset: offset + def_len]))
            #         else:
            #             res.append(decrypter.decrypt(encrypted_byte[offset:], 'failure'))
                    
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





