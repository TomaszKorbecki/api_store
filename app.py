import os
from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from dotenv import load_dotenv
from db import db
from blocklist import BLOCKLIST

import models

from resources.item import blp as ItemBlueprint
from resources.store import blp as StoreBluprint
from resources.tag import blp as TagBluprint
from resources.user import blp as UserBluprint
load_dotenv()

def create_app(db_url=None):
    app = Flask(__name__)

    app.config["PPROPAGATE_EXCEPTIONS"] = True
    app.config["API_TITLE"] = "Stores Rest API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL", "sqlite:///data.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "default")
    db.init_app(app)
    migrate = Migrate(app, db)
    jwt = JWTManager(app)

    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        if identity == 1:
            return {"is_admin" : True}
        return {"is_admin": False}

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_head, jwt_payload):
        return jwt_payload["jti"] in BLOCKLIST
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header,jwt_payload):
        return(
            jsonify({
                "description": "The token is not fresh",
                "error": "fresh_token_required"
            })
        )
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return(
            {"description":"The token has been revoked.", "error": "token_revoked"},
            401
            )
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return(
            jsonify(
            {
                "message":"Signature verification failed", "error":"invalid_token"
            },
            401
            ))
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return(
            {
                "message":"Signature verification failed.", "error": "invalid_token"
            },
            401
        )
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return(
            jsonify(
                {"description": "Request does not contatin an access token",
                 "error": "autohization_required"}
            )
        ) 

    api = Api(app)

    api.register_blueprint(ItemBlueprint)
    api.register_blueprint(StoreBluprint)
    api.register_blueprint(TagBluprint)
    api.register_blueprint(UserBluprint)

    return app