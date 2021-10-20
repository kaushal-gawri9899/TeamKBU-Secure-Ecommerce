from flask import Flask
import bcrypt
from flask_pymongo import PyMongo

from bson.json_util import dumps

from bson.objectid import ObjectId

from flask import jsonify, request

from pymongo import MongoClient

from flask_jwt_extended import JWTManager, jwt_required, create_access_token

import werkzeug.exceptions
from flask_mongoengine import MongoEngine

app = Flask(__name__)


client = MongoClient('YOUR_MONGODB_URI')

db = client.get_default_database()

items = db['Items']
zhiffy = db['Zhiffy']
cart = db['Cart']
order = db['Order']

app = Flask(__name__)
jwt = JWTManager(app)
app.config["MONGO_URI"] = "YOUR_MONGODB_URI"
app.config["JWT_SECRET_KEY"] = "ACCESS_KEY_999"
mongo = PyMongo(app)

