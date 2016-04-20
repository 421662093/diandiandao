#!/usr/bin/env python
#-*- coding: utf-8 -*-
from flask import g, jsonify
from flask.ext.httpauth import HTTPBasicAuth  # http安全认证
from ..models import User, AnonymousUser
from . import api
from .errors import unauthorized, forbidden

auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username_or_token, password):
    #print username_or_token+'___'+password
    #username_or_token = 'eyJhbGciOiJIUzI1NiIsImV4cCI6MTQzOTI4MjY4MywiaWF0IjoxNDM5Mjc5MDgzfQ.eyJpZCI6NzF9.GPqrpHaqL1d42vZaewOa10XQKjyswXz0dDnz5gYlve0'
    #password = '123456'

    unlen = len(username_or_token)
    if unlen>0:
        user =None
        if unlen==11 or unlen<50:
            # try to authenticate with username/password
            user = User.getinfo_app(username_or_token)
            if not user or not user.verify_password(password):
                return False
            g.token_used = False
        else:
            user = User.verify_auth_token(username_or_token)
            if not user:
                return False
            g.token_used = True
        g.current_user = user
    else:
        g.current_user = None
        return False

    return True
    '''
    if email_or_token == '':
        g.current_user = AnonymousUser()
        return False
    if password == '':
        print email_or_token + "_____________"
        g.current_user = User.verify_auth_token(email_or_token)
        g.token_used = True
        return g.current_user is not None

    user = User.objects(email=email_or_token).first()

    if not user:
        return False
    g.current_user = user
    g.token_used = False
    return user.verify_password(password)
    '''


@auth.error_handler
def auth_error():
    return jsonify({'error':'nologin'})
    #return unauthorized('Invalid credentials')

'''
@api.before_request
@auth.login_required
def before_request():
    #print g.current_user.is_administrator()
    if not g.current_user.is_administrator() and not g.current_user.confirmed:
        return forbidden('Unconfirmed account')
    ''''''
    if not g.current_user.is_anonymous() and \
            not g.current_user.confirmed:
        return forbidden('Unconfirmed account')
    ''''''
'''

@api.route('/token', methods = ['GET','POST'])
@auth.login_required
def get_token():
    '''
    获取验证用户token

    URL:/token
    参数:
        无
    返回值
        token #身份验证字符串
    '''
    if g.token_used:
        return unauthorized('Invalid credentials') #帐号或密码错误,或身份过期
    return jsonify({'token': g.current_user.generate_auth_token(
        expiration=2592000), 'expiration': 2592000,'_id': g.current_user.id})
    '''
    if g.current_user.is_anonymous() or g.token_used:
        return unauthorized('Invalid credentials')
    return jsonify({'token': g.current_user.generate_auth_token(
        expiration=3600), 'expiration': 3600})
    '''
