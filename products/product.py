"""
Importing the necessary Libraries
"""
from flask import Flask
from flask import Blueprint
import bcrypt
from flask_pymongo import PyMongo

from bson.json_util import dumps

import bson.errors

from bson.objectid import ObjectId

from flask import jsonify, request

from pymongo import MongoClient

from flask_jwt_extended import JWTManager, jwt_required, create_access_token

import config
import werkzeug.exceptions as ex

"""
Creating a blueprint for all the product routes
This blueprint would be registered in main application
"""
product_bp = Blueprint('product_bp', __name__)


"""
Insert Product API route : Adds a product or items to the collection with pre decided attributes. 
Pre decided attributes are used to the best of my knowledge
Validates empty string for details and converts the values to a dictionary
Dictionary is then added to the "items" collection
Returns a success message
A decorator is added to add security for the current method, user with only access token provided during login can perform operation
"""
@product_bp.route("/insertProducts", methods=["POST"])
@jwt_required()
def insertProducts():
    try:
        """
        Using Json body
        """
        # _json = request.json
        # item_category = _json["category"]
        # item_brand = _json["brand"]
        # item_model = _json["model"]
        # item_purchase = _json["purchase_date"]
        # item_price = _json["price"]
        # item_location = _json["location"]
      
        item_category = request.form["category"]
        item_brand = request.form["brand"]
        item_model = request.form["model"]
        item_purchase = request.form["purchase_date"]
        item_price = request.form["price"]
        item_location = request.form["location"]

        if item_category and item_brand and item_purchase and item_purchase and item_price and item_location and request.method == 'POST':
            if 'product_image' in request.files:
                product_img = request.files['product_image']
                config.mongo.save_file(product_img.filename, product_img)
                
                
                item_data = dict(category=item_category, brand=item_brand, model=item_model, purchase_date=item_purchase, price=item_price, location=item_location, product_image=product_img.filename)
        
                id = config.items.insert_one(item_data)
                return jsonify(message="Item Added Successfully", flag=True), 201
    
        return jsonify(message="Empty Fields Found. Please Fill all Details,", flag=False), 404
    
    except (ex.BadRequestKeyError, KeyError):
        return internal_error()




@product_bp.errorhandler(500)
def internal_error(error=None):
    message= {
        'status': 404,
        'message': "Invalid Fields Provided. Please Retry!"
    }

    resp = jsonify(message)
    return resp

@product_bp.errorhandler(500)
def internal_error_invalid_ID(error=None):
    message= {
        'status': 404,
        'message': "Invalid ID Provided. It must be a 12-byte input or a 24-character hex string!"
    }

    resp = jsonify(message)
    return resp


"""
See All Products Route : Returns a json string which is converted using json.dumps() that converts bson to json
A json string containing all the product details is returned
"""
@product_bp.route("/seeAllProducts", methods=["GET"])
def getAllItems():
    allItems = config.items.find()
    results = dumps(allItems)
    return results

"""
See Details of Given Product Route : Returns a json string containing details of given product based on product ID
"""
@product_bp.route("/seeAllProducts/<pid>", methods=["GET"])
def getItemDetails(pid):
    try:
        item = config.items.find_one({"_id": ObjectId(pid)})
        
        if not item:
            return jsonify(message="Invalid ID provided", flag=False), 404

        result = dumps(item)
        return result
    
    except (ex.BadRequestKeyError, KeyError):
        return internal_error()
    
    except bson.errors.InvalidId:
        return internal_error_invalid_ID()

@product_bp.route('/seeAllProducts/image/<pid>')
def getItemImage(pid):
    try:
        item = config.items.find_one({"_id": ObjectId(pid)})

        if not item:
            return jsonify(message="Invalid ID provided", flag=False), 404

        img = item["product_image"]

        return config.mongo.send_file(img)
    
    except (ex.BadRequestKeyError, KeyError):
        return internal_error()
    
    except bson.errors.InvalidId:
        return internal_error_invalid_ID()

"""
Delete Product of Given Route : Deletes a given product based on product ID
Returns a json string with success method
"""
@product_bp.route("/deleteProduct/<pid>", methods=["DELETE"])
def deleteGivenItem(pid):
    
    try:
        
        item = config.items.delete_one({"_id": ObjectId(pid)})
        result = jsonify("Item with ID {"+str(ObjectId(pid))+"} Deleted Successfully.", flag=True), 202
        if not item:
            return jsonify(message="Invalid ID provided", flag=False), 404

        result.status_code = 202

        return result
    
    except (ex.BadRequestKeyError, KeyError):
        return internal_error()
    
    except bson.errors.InvalidId:
        return internal_error_invalid_ID()
    

"""
Change Item Detail API route : Used to update the details of items stored in collection
Uses PUT Http request to replace the current details with the newly updated one
Returns a success message
"""
@product_bp.route("/changeItemDetails/<pid>", methods=["PUT"])
def changeItemDetail(pid):

    try:
        _json = request.json

        item_category = _json["category"]
        item_brand = _json["brand"]
        item_model = _json["model"]
        item_purchase = _json["purchase_date"]
        item_price = _json["price"]
        item_location = _json["location"]

        if item_category and item_brand and item_model and item_purchase and item_price and item_location:
            update_item = config.items.update_one({'_id': ObjectId(pid)}, {"$set": {'category': item_category, 'brand': item_brand, 'model': item_model, 'purchase_date': item_purchase, 'price': item_price, 'location': item_location}})
            return jsonify(message="Item Details with ID {"+str(ObjectId(pid))+"} Updated.", flag=True), 200
        else:
            return jsonify(message="Invalid Details Provided. Please retry", flag=False), 404

    except (ex.BadRequestKeyError, KeyError):
        return internal_error()

        


