from flask import Flask
import bcrypt
from flask_pymongo import PyMongo

from bson.json_util import dumps

from bson.objectid import ObjectId

from flask import jsonify, request

from pymongo import MongoClient

from flask_jwt_extended import JWTManager, jwt_required, create_access_token

import werkzeug.exceptions


# from flask_mongoengine import MongoEngine

app = Flask(__name__)
# jwt = JWTManager(app)
# # app.config["MONGO_URI"] = "mongodb://localhost:27017/application_db"
# # mongo = PyMongo(app)

# app.config["JWT_SECRET_KEY"] = "ACCESS_KEY_999"

# app.config['MONGODB_SETTINGS'] = {
#     'db': 'your_database',
#     'host': 'localhost',
#     'port': 27017
# }
# db = MongoEngine()
# db.init_app(app)

client = MongoClient("mongodb://127.0.0.1:27017") #host uri  
db = client.mymongodb #Select the database  
todos = db.todo #Select the collection name  

#Use MongoClient to connect to the local MongoDB instance
# dbClient = MongoClient("mongodb://localhost:27017/")

# #Create a database for the application
# db = dbClient["application_db"]

# #database created will have multiple collections, 
# # one for storing all the registered user details 
# # other for storing all the product details
# zhiffy = db["Zhiffy"]
# items = db["Items"]

#Creating a flask app and configuring that with JWTManager to secure the entire app
app = Flask(__name__)
# jwt = JWTManager(app)
# # app.config["MONGO_URI"] = "mongodb://localhost:27017/application_db"
# # mongo = PyMongo(app)

# app.config["JWT_SECRET_KEY"] = "ACCESS_KEY_999"