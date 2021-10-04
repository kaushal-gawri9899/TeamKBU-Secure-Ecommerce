"""
Importing the necessary Libraries
"""
from user.user import user_bp
from products.product import product_bp
from cart.cart import cart_bp
import config
import os

"""
Registering both the blueprints for users and products
"""
config.app.register_blueprint(user_bp)
config.app.register_blueprint(product_bp)
config.app.register_blueprint(cart_bp)
config.app.secret_key = "AppleMangoBanana"

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    config.app.run(host='0.0.0.0', port=port)


        




