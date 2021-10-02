#!/usr/bin/env python3
#coding=utf-8
#author:yannanxiu
"""
create_rsa_key ()-Create rsa key
my_encrypt_and_decrypt ()-Encryption and decryption test
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto import Random
def create_rsa_key (password="123456"):
  """
  Create rsa key
  Step description:
  1. Import rsa from the crypto.publickey package to create a password
  Generate 1024/2048-bit rsa keys
  3. Invoke the exportkey method of the rsa key instance, passing in the three parameters of the password, the pkcs standard used, and the encryption scheme.
  4. Write the private key to a file on disk.
  5. Use the method chain to call the publickey and exportkey methods to generate the public key.
Write to a file on disk.
  """
  key=RSA.generate (2048)
  encrypted_key=key.export_key (passphrase=password,pkcs=8,  protection="scryptandaes128-cbc")
  with open ("my_private_rsa_key.bin", "wb") as f:
    f.write (encrypted_key)
  with open ("my_rsa_public.pem", "wb") as f:
    f.write (key.publickey (). exportKey ())
def encrypt_and_decrypt_test (password="123456"):
  #Load public key
  recipient_key=RSA.import_key (
    open ("my_rsa_public.pem"). read ()
  )
  cipher_rsa=PKCS1_v1_5.new (recipient_key)
  en_data=cipher_rsa.encrypt (b"123456")
  print(len (en_data), en_data)
  #Read key
  private_key=RSA.import_key (
    open ("my_private_rsa_key.bin"). read (),    passphrase=password
  )
  cipher_rsa=PKCS1_v1_5.new (private_key)
  data=cipher_rsa.decrypt (en_data, Random.new().read(256))
  print (data)
if __name__ == "__main__":
  create_rsa_key ()
  encrypt_and_decrypt_test ()