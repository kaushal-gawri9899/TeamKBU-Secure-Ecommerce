"""
Importing the necessary Libraries
"""
from user.user import user_bp
from products.product import product_bp
import config

"""
Registering both the blueprints for users and products
"""
config.app.register_blueprint(user_bp)
config.app.register_blueprint(product_bp)


if __name__ == '__main__':
    config.app.run(host="localhost", debug=True)


        




