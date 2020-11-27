import hashlib

from flask import Flask, request, jsonify
from flask_restful import Api, Resource, fields, reqparse
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, jwt_refresh_token_required)

from passlib.apps import custom_app_context as pwd_context

global hashlib
global request
global create_access_token
global jsonify
global get_jwt_identity
global reqparse

class manage_security_keys():
    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)
    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
app = Flask("__main__")
api = Api(app)

class API(Resource):
    def get(self):
        return {"Test1": "HI"}

# Code from Here was used: https://flask-jwt-extended.readthedocs.io/en/stable/basic_usage/

# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    #if username != 'test' or password != 'test':
    #    return jsonify({"msg": "Bad username or password"}), 401
        
    user_input = ""
    print("Someone Is Attempting to LOGIN to your server! Do you approve y or n?")
    print("The username is:", username, "and the password is:", password)
    while True:
        user_input = input(": ")
        if user_input.upper() == "Y":
            # Identity can be any data that is json serializable
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token), 200
        else:
            if universal.databaseRef.direct_sqlite("SELECT * FROM Web_Logins WHERE name = " + str(username) + " AND password = " + str(password))
            universal.log_write.write("Someone attempted to access the REST API. Username: " + str(username) + " Password: " + str(password))
            return jsonify({"msg": "Denied by Server"}), 403

    

# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/protected/pull_file', methods=['GET'])
@jwt_required
def pull_file():
    #if not request.is_json:
    #    return jsonify({"msg": "Missing JSON in request"}), 400
    data = {}
    data["file_id"] = request.args.get('file_id')
    data["hashs"] = request.args.get('hash')
    data["filename"] = request.args.get('filename')
    data["size"] = request.args.get('size')
    data["ext"] = request.args.get('ext')
    
    key_list = list(data.keys()) 
    val_list = list(data.values()) 
    
    for each in val_list:
        if isinstance(each, str):
            
            data_to_pass = {key_list[val_list.index(each)]: data[key_list[val_list.index(each)]]}

            data_pulled = universal.databaseRef.pull_data("File", key_list[val_list.index(each)], data[key_list[val_list.index(each)]])

            if len(data_pulled) == 0:
                return {"msg": "No Data Found"}
            else:
                _json = {}
                count = 0
                for each in data_pulled:
                    temp_dict = {}
                    temp_dict["file_id"] = each[0]
                    temp_dict["hashs"] = each[1]
                    temp_dict["filename"] = each[2]
                    temp_dict["size"] = each[3]
                    temp_dict["ext"] = each[4]
                    temp_dict["tags"] = universal.databaseRef.optimized_file_tag_pull(each[0])
                    _json[count] = temp_dict
                    count += 1
                return _json, 200

    return jsonify(data), 200

def manage_db():
    universal.databaseRef.create_table("Web_Logins", {"username": "text", "password": "text", "access": "text", "salt": "text"})

print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("DONT EXPOSE THIS TO THE INTERNET... THE JWT TOKENIZER KEY HASNT BEEN CHANGED YET.")
print("lmao probably SQL INJECTION aswell need to sanitize...")
manage_db()

api.add_resource(API, "/api")
#TODO CHANGE JWT SECURITY KEY TO SOMTHING RANDOM
app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)
app.run(host="127.0.0.1", debug=False)

storage = None

hooks = {}

