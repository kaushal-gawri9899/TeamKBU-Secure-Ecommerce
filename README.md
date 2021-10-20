# A Secure Ecommerce System


## :pencil: PROJECT IDEA

Build a secure ecommerce system with secure payment gateway where users can access a product catalog and purchase products by adding them in their individual cart. The product catalog provides various sports items whose high level description can be provided through the individual product page. Secure communication between the client and server is the major goal of the project by using public key cryptography (RSA)

## :pencil: Goal

The goal of the project is to build secure communication between client and server using public key cryptography. A secure client/server communication is developed with an agreement on using a session key which is unique to every user and is valid only for current session, i.e, for the time user is logged in. The session key is implemented using DES where all the request are encrypted on the client side(and decrypted at server side)  and all the responses are encrypted on the server side(and decrypted on the client side). The session key is generated on the client side and data payload for request and response is added to the session key which is then shared using public key cryptography for secure communication.  

## :pencil: FEATURES

(1) Allow users to sign up and login to the application

(2) Allow users to access the homepage displaying the product catalog

(3) Allow users to view high level description of each product from their individual pages

(4) Allow users to add items to the cart for future purchase

(5) Allow users to increase or decrease the quantity of items in the cart

(6) Allow users to delete an item from their cart

(7) Allow users to make payment securely with high level validation of payment details

(8) Allow users to download an invoice of the last order created through the application with high level description


# Backend (Python/Flask)
- Backend contains fully functional restful APIS with necessary CRUD operations and uses MongoDB database (NoSQL) to store data. 

Python Version used: 3.7.7
Flask Version used: 1.1.2

To run the backend, you have to run the following commands: 
-   $ pip3 install -r requirements.txt 
-   $ python3 application.py

# Github URL:
https://github.com/kaushal-gawri9899/TeamKBU-Secure-Ecommerce

# Application URL: 
http://secure-kpa.herokuapp.com/
