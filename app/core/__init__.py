from flask import Blueprint

core = Blueprint('core', __name__)

from . import common, tasks#,search,wxpayapi, 
