from flask import jsonify
import logging
from app.exceptions import ValidationError
from . import api

def not_allowed(message):
    response = jsonify({'error': 'Method Not Allowed', 'message': message})
    response.status_code = 405
    logging.error('405 - '+message)
    return response

def bad_request(message):
    response = jsonify({'error': 'bad request', 'message': message})
    response.status_code = 400
    logging.error('400 - '+message)
    return response


def unauthorized(message):
    response = jsonify({'error': 'unauthorized', 'message': message})
    response.status_code = 401
    logging.error('401 - '+message)
    return response


def forbidden(message):
    response = jsonify({'error': 'forbidden', 'message': message})
    response.status_code = 403
    logging.error('403 - '+message)
    return response


@api.errorhandler(ValidationError)
def validation_error(e):
    logging.error(bad_request(e.args[0]))
    return bad_request(e.args[0])
