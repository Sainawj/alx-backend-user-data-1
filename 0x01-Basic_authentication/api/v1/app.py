#!/usr/bin/env python3
"""Route module for the API, defining the application setup,
   error handling, and user authentication.
"""
import os
from os import getenv
from flask import Flask, jsonify, abort, request
from flask_cors import CORS
from api.v1.views import app_views
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth

# Initialize the Flask app and register the blueprint for views
app = Flask(__name__)
app.register_blueprint(app_views)

# Enable CORS for all routes under "/api/v1/*"
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Determine the authentication type based on environment variable
auth = None
auth_type = getenv('AUTH_TYPE', 'auth')
if auth_type == 'auth':
    auth = Auth()
if auth_type == 'basic_auth':
    auth = BasicAuth()

@app.errorhandler(404)
def not_found(error) -> str:
    """404 Not found error handler.
    Returns JSON error response for missing resources.
    """
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(401)
def unauthorized(error) -> str:
    """401 Unauthorized error handler.
    Returns JSON error response for unauthorized access.
    """
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(error) -> str:
    """403 Forbidden error handler.
    Returns JSON error response for forbidden access.
    """
    return jsonify({"error": "Forbidden"}), 403

@app.before_request
def authenticate_user():
    """Authenticates a user before processing a request.
    Checks for authorization headers and validates user access.
    """
    if auth:
        # Paths that do not require authentication
        excluded_paths = [
            '/api/v1/status/',
            '/api/v1/unauthorized/',
            '/api/v1/forbidden/',
        ]
        # Check if path requires authentication
        if auth.require_auth(request.path, excluded_paths):
            auth_header = auth.authorization_header(request)
            user = auth.current_user(request)
            # Abort with 401 if authorization header is missing
            if auth_header is None:
                abort(401)
            # Abort with 403 if user is not authorized
            if user is None:
                abort(403)

if __name__ == "__main__":
    # Get host and port from environment, defaulting to "0.0.0.0" and "5000"
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
