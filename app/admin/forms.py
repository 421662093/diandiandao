#!/usr/bin/env python
#-*- coding: utf-8 -*-
from flask.ext.wtf import Form

from wtforms import IntegerField, StringField, TextAreaField, BooleanField, SelectField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp
from wtforms import ValidationError, validators
from flask.ext.pagedown.fields import PageDownField
from ..models import User
from config import config
conf = config['default']

class EditUserForm(Form):
	name = StringField('name', validators=[Length(0, 24)])
	username = StringField('username', validators=[Length(0, 64)])
	#email = StringField('email', validators=[Length(0, 64)])
	password = StringField('password', validators=[Length(0, 128)])
	#confirmed = SelectField('confirmed', choices=[(1, True),(0, False)], coerce=int,validators=[validators.optional()])
	#domainid = SelectField('domainid', choices=[conf.DOMAIN], coerce=int,validators=[validators.optional()])
    #industryid = SelectField('industryid', choices=[conf.INDUSTRY], coerce=int,validators=[validators.optional()])
	#sex = SelectField('sex', choices=[(1, '男'),(0, '女')], coerce=int,validators=[validators.optional()])
	#job = StringField('job', validators=[Length(0, 64)])

class EditTopicForm(Form):

    eid = IntegerField('eid')
    title = StringField('title', validators=[Length(0, 64)])
    #sintro = StringField('intro', validators=[Length(0, 256)])
    #content = StringField('content')
    call = IntegerField('call')
    meet = IntegerField('meet')
    #expert = StringField('expert')
    #background = StringField('background', validators=[Length(0, 256)])
    topic_count = IntegerField('topic_count')
    topic_total = IntegerField('topic_total')

class EditInventoryForm(Form):

    title = StringField('title', validators=[Length(0, 64)])
    sort = IntegerField('sort')

class EditRoleForm(Form):

    name = StringField('name', validators=[Length(0, 64)])
    default = SelectField(
        'default', choices=[(1, True),
                              (0, False)],
        coerce=int,
        validators=[validators.optional()])

class EditAdForm(Form):

    title = StringField('title', validators=[Length(0, 64)])