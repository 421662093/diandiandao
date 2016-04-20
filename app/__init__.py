#!/usr/bin/env python
#-*- coding: utf-8 -*-
from flask import Flask
from flask.ext.mongoengine import MongoEngine
import redis

import os 
# from flask.ext.bootstrap import Bootstrap
# from flask.ext.mail import Mail
# from flask.ext.sqlalchemy import SQLAlchemy
from config import config
from flask.ext.login import LoginManager
from datetime import datetime
#from core import search

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
conf = config['default']

'''
from flask.ext.moment import Moment  # 集成moment.js到Jinja2模板的Flask扩展。
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.pagedown import PageDown
bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
pagedown = PageDown()
'''

db = MongoEngine()

#rs= redis.StrictRedis(host='localhost', port=6379, db=0)
#searchwhoosh = search.WhooshExpert()
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    # app.config.from_pyfile('the-config.cfg')

    config[config_name].init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    #searchwhoosh.rebuild_index()
    #searchwhoosh.update({'_id':1111,'n':u'蜡笔小新','j':u'首席执行官'})
    #print searchwhoosh.search(u'小',1)
    #from .models import UserTest
    #whooshalchemy.whoosh_index(app, UserTest)
    '''
    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    pagedown.init_app(app)
    if not app.debug and not app.testing and not app.config['SSL_DISABLE']:
        from flask.ext.sslify import SSLify
        sslify = SSLify(app)
    '''


    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .core import core as core_blueprint
    app.register_blueprint(core_blueprint)

    from .admin import admin as admin_blueprint
    app.register_blueprint(admin_blueprint, url_prefix='/admin')

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .api_1_0 import api as api_1_0_blueprint
    app.register_blueprint(api_1_0_blueprint, url_prefix='/api/v1.0')

    return app