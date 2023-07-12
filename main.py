from flask import Flask, json, request, abort, jsonify
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    create_access_token, create_refresh_token, JWTManager, jwt_required, get_jwt_identity, get_jwt
)

from argon2 import PasswordHasher
from datetime import timedelta
from bson import ObjectId
from gql import gql, Client
from redis import Redis
from gql.transport.requests import RequestsHTTPTransport
import requests

transport = RequestsHTTPTransport(url='https://rickandmortyapi.com/graphql')

client = Client(transport=transport, fetch_schema_from_transport=True)

redis = Redis(host='localhost', port=6379, decode_responses=True)


ACCESS_EXPIRES = timedelta(seconds=10)
REFRESH_EXPIRES = timedelta(seconds=30)

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/qwerty'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_SECRET_KEY'] = 'supersecret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_EXPIRES
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = REFRESH_EXPIRES

jwt_manager = JWTManager(app)
mongo = PyMongo(app)
jwt_redis_blocklist = Redis(
    host='localhost',
    port=6379,
    decode_responses=True,
)

ph = PasswordHasher()


@app.route('/me')
@jwt_required()
def me():
    id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(id)})
    return jsonify(
        name=user['name'],
        last_name=user['last_name'],
        email=user['email']
    )


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)


@jwt_manager.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header: dict, jwt_payload: dict) -> bool:
    jti = jwt_payload['jti']
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None


@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jwt = get_jwt()
    jti = jwt['jti']
    jwt_redis_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
    return jsonify(msg='Access token revoked')


@jwt_manager.user_lookup_loader
def user_lookup_callback(jwt_header, jwt_data):
    identity = jwt_data['sub']
    return mongo.db.users.find_one({'_id': ObjectId(identity)})


@app.route('/characters', methods=['GET'])
@jwt_required()
def auth_data():
    page = request.args.get('page')
    page = 1 if page is None else int(page)
    if (characters := redis.get(page)) is not None:
        return jsonify(json.loads(characters))
    # params = {'page': page}
    res = requests.get(
        f'https://rickandmortyapi.com/api/character?page={page}')
    results = res.json()['results']
    # q = gql(
    #     """
    #     query GetCharacters ($page: Int!) {
    #         characters (page: $page) {
    #             results {
    #                 name
    #                 status
    #                 species
    #                 gender
    #                 image
    #             }
    #         }
    #     }
    #     """
    # )
    # data = client.execute(q, variable_values=params)
    # characters = data['characters']['results']
    redis.set(page, json.dumps(results))
    return jsonify(results)


@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    user = mongo.db.users.find_one({'email': email})
    if user is None:
        return abort(401)
    try:
        ph.verify(user['password'], password)
    except:
        abort(401)
    access_token = create_access_token(identity=str(user['_id']))
    refresh_token = create_refresh_token(identity=str(user['_id']))

    return jsonify(
        access_token=access_token,
        token_type='Bearer',
        expires_in=int(ACCESS_EXPIRES.total_seconds()),
        refresh_token=refresh_token
    )


@app.route('/register', methods=['POST'])
def register():
    name = request.json.get('name')
    last_name = request.json.get('last_name')
    email = request.json.get('email')
    password = request.json.get('password')
    user = mongo.db.users.find_one({'email': email})
    if user is not None:
        abort(409)  # Conflict
    hashed_password = ph.hash(password)
    user = {'_id': ObjectId(), 'name': name, 'last_name': last_name,
            'email': email, 'password': hashed_password}
    mongo.db.users.insert_one(user)
    return 'user created', 200


if __name__ == '__main__':
    app.run(debug=True)
