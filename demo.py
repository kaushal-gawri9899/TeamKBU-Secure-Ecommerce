#!/usr/bin/env python3
#coding=utf-8
#author:yannanxiu
import os
from flask import Flask, render_template, request, current_app
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
import base64
from urllib import parse
#Get the current path
curr_dir=os.path.dirname (os.path.realpath (__file__))

private_key_file=os.path.join (curr_dir, "my_private_rsa_key.bin")
public_key_file=os.path.join (curr_dir, "my_rsa_public.pem")

app=Flask (__name__)

def decrypt_data (inputdata, code="123456"):
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
  
@ app.route ("/", methods=["GET", "POST"])
def rsa ():
  public_key=None
  print("Here")
  if "GET" == request.method:
    with open (public_key_file) as file:
      public_key=file.read ()
  elif "POST" == request.method:
    username=request.values.get ("username")
    password=request.values.get ("passwd")
    token=request.values.get("token")
    #current_app.logger.debug ("username:" + username + "\ n" + "password:" + password)
    current_app.logger.debug ("username:" + username + "\ n" + "password:" + password + "\ n" + "token:" + token)

    #decrypt
    #print(username)
    username_ret=decrypt_data (username)
    password_ret=decrypt_data (password)
    token_ret=decrypt_data (token)

    print("\nUsername", username_ret.decode())
    print("\nPassword", password_ret.decode())
    print("\nToken", token_ret.decode())

    if username_ret and password_ret:
      current_app.logger.debug (username_ret.decode () + "" + password_ret.decode ())

  return render_template ("rsa_view.html", public_key=public_key)

@ app.route ("/js_rsa_test", methods=["get", "post"])
def js_rsa_test ():
  return render_template ("js_rsa_test.html")

if __name__ == '__main__':
    app.run(host="localhost", debug=True)
