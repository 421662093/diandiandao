#!/usr/bin/env python
#-*- coding: utf-8 -*-
from datetime import datetime
from mongoengine import EmbeddedDocument, EmbeddedDocumentField,Q
from flask import g
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (
    TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired,URLSafeSerializer)
import hashlib

'''
from markdown import markdown
import bleach  # html 清除工具
'''
from app.exceptions import ValidationError
from flask import current_app, request, url_for
from flask.ext.login import UserMixin, AnonymousUserMixin
from . import db,conf, login_manager#,searchwhoosh
from core import common
import json
import logging
#import cpickle as pickle

class Permission:
    VIEW = 0x01 # 查看
    EDIT = 0x02 # 编辑
    DELETE = 0x04 # 删除
    ADMINISTER = 0x80

class RolePermissions(db.EmbeddedDocument):  # 角色权限
    user = db.IntField(default=0, db_field='u') #用户
    topic = db.IntField(default=0, db_field='t') #话题
    inventory = db.IntField(default=0, db_field='i') #清单
    appointment = db.IntField(default=0, db_field='a') #预约
    ad = db.IntField(default=0, db_field='ad') #广告
    role = db.IntField(default=0, db_field='r') #角色
    log = db.IntField(default=0, db_field='l') #日志
    expertauth = db.IntField(default=0, db_field='ea') #审核专家

    def to_json(self):
        json_rp = {
            'user': self.user,
            'topic': self.topic,
            'inventory': self.inventory,
            'appointment': self.appointment,
            'ad': self.ad,
            'role': self.role,
            'log': self.log,
            'expertauth': self.expertauth
        }
        return json_rp

class Role(db.Document):
    __tablename__ = 'roles'
    meta = {
        'collection': __tablename__,
    }
    _id = db.IntField(primary_key=True)
    name = db.StringField(max_length=64, required=True,db_field='n')
    default = db.BooleanField(default=False, db_field='d')
    permissions = db.EmbeddedDocumentField(
        RolePermissions, default=RolePermissions(), db_field='p')  # 统计
    CACHEKEY = {
        'list':'rolelist',
        'item':'roleitem'
    }
    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.VIEW | Permission.EDIT | Permission.DELETE | Permission.ADMINISTER, True),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role()
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            role._id = collection.get_next_id('role')
            role.name = '12@qq.com'
            role.save()
            
    @staticmethod
    def getlist():
        return Role.objects().limit(30)
            # rv = mc.get(Role.CACHEKEY['list'])
            # rv = rs.get(Role.CACHEKEY['list'])
            #if rv is None:
        '''
            rv = Role.objects().limit(30)
            
            temp =  json.dumps([item.to_json() for item in rv])
            try:
                mc.set(Role.CACHEKEY['list'],temp)
            except Exception,e:
                logging.debug(e)
                return rv
            #rs.set(Role.CACHEKEY['list'],temp)
        else:
            rv = json.loads(rv)
        '''

    def editinfo(self):
        #mc.delete(Role.CACHEKEY['list'])
        if self._id > 0:
            update = {}
            # update.append({'set__email': self.email})

            if len(self.name) > 0:
                update['set__name'] = self.name
            update['set__default'] = self.default
            update['set__permissions'] = self.permissions
            Role.objects(_id=self._id).update_one(**update)
            return 1
        else:
            self._id = collection.get_next_id(self.__tablename__)
            self.save()
            return self._id

    @staticmethod
    def getinfo(rid):
        #获取指定id 角色信息
        #return Role.objects(_id=rid).first()
        #'''
        if rid>0:
            rlist = Role.getlist()
            for item in rlist:
                if item['_id']==rid:
                    return item
            return None
        else:
            return None
        #'''
    def to_json(self):
        json_role = {
            '_id': self.id,
            'name': self.name.encode('utf-8'),
            'default': self.default,
            'permissions': self.permissions.to_json()
        }
        return json_role
    '''
    def __repr__(self):
        return '<Role %r>' % self.name # 角色权限
    '''

class UserStats(db.EmbeddedDocument):  # 会员统计
    lastaction = db.IntField(default=0, db_field='la')  # 最后更新时间
    message_count = 0  # 消息个数

    def to_json(self):
        json_us = {
            'meet': self.meet
        }
        return json_us

class SNS(db.EmbeddedDocument):  # 第三方社交登录
    sina = db.StringField(default='', db_field='s') 
    qq = db.StringField(default='',  db_field='q') 
    weixin = db.StringField(default='', db_field='w') 
    token = db.StringField(default='',  db_field='t')  #token

class User(UserMixin, db.Document):  # 会员
    __tablename__ = 'users'
    meta = {
        'collection': __tablename__,
    }
    _id = db.IntField(primary_key=True)
    email = db.StringField(default='', max_length=64, db_field='e')  # 邮箱
    weixin = db.StringField(default='', max_length=64, db_field='wx')  # 微信
    qq = db.StringField(default='', max_length=10, db_field='qq')  # QQ
    name = db.StringField(
        default='', max_length=64, required=True, db_field='n')  # 姓名
    username = db.StringField(
        default='', max_length=64, required=True, db_field='un')  # 帐号
    password_hash = db.StringField(
        default='', required=True, max_length=128, db_field='p')  # 密码
    role_id = db.IntField(default=0, db_field='r')  # 用户组id 1管理员 2专家用户 3普通用户
    role = None  # 用户组权限
    sex = db.IntField(default=1, db_field='s')  # 性别 1男 0女
    grade = db.IntField(db_field='g')  # 评级
    geo = db.PointField(default=[0, 0], db_field='ge')  # 坐标
    stats = db.EmbeddedDocumentField(
        UserStats, default=UserStats(), db_field='st')  # 统计
    date = db.IntField(default=0, db_field='d')  # 创建时间
    intro = db.StringField(default='', db_field='i')  # 简介
    avaurl = db.StringField(default='', db_field='a')  # 头像地址
    state = db.IntField(default=1, db_field='sta')# 状态 1 正常  -1新增  -2待审核 0暂停
    money = db.IntField(default=0, db_field='m')  # 账户余额
    sns = db.EmbeddedDocumentField(SNS, default=SNS(), db_field='sn')
    

    @staticmethod
    def getlist_app(roid=2,index=1,count=10):
        # 用于APP接口
        pageindex =(index-1)*count
        return User.objects(role_id=roid,state=1).order_by("sort").skip(pageindex).limit(count)

    @staticmethod
    def getlist(roid=0,index=1,count=10,sort='-_id'):
        #用于后端
        #.exclude('password_hash') 不包含字段
        pageindex =(index-1)*count
        if roid == 0:
            return User.objects.order_by(sort).skip(pageindex).limit(count)
        else:
            return User.objects(role_id=roid).order_by(sort).skip(pageindex).limit(count)

    @staticmethod
    def getcount(roid=0):
    	if roid == 0:
            return User.objects.count()
        else:
            return User.objects(role_id=roid).count()

    @staticmethod
    def getlist_uid_app(uidlist, feild=[], count=10):
        # 获取指定id列表的会员数据 用于后端
        #.exclude('password_hash') 不包含字段
        return User.objects(_id__in=uidlist,state=1).limit(
            count).exclude('password_hash')

    @staticmethod
    def getlist_uid(uidlist, feild=[], count=10):
        # 获取指定id列表的会员数据
        #.exclude('password_hash') 不包含字段

        ulist = []

        for item in uidlist:
            uinfo = User.objects(_id=item).exclude('password_hash').first()
            if uinfo!=None:
                ulist.append(uinfo)

        return ulist
        #return User.objects(_id__in=uidlist).limit(
        #    count).exclude('password_hash')

    @staticmethod
    def getinfo_admin(username):
        # 获取指定id 管理员(web后台)

        query = Q(username=username) & (Q(role_id=1) | Q(role_id__gte=4))

        u_info = User.objects(query).first()

        if u_info is not None:
            u_info.role = Role.getinfo(u_info.role_id)
        return u_info

    @staticmethod
    def getinfo_app(username):
        # 获取指定id 用户(APP)

        query = Q(username=username) # & (Q(role_id=2) | Q(role_id=3))

        u_info = User.objects(query).first()

        if u_info is not None:
            u_info.role = Role.getinfo(u_info.role_id)
        return u_info

    @staticmethod
    def getinfo(uid, feild=[]):  # 获取指定id列表的会员数据
        #.exclude('password_hash') 不包含字段
        u_info = User.objects(_id=uid).exclude('password_hash').first()
        if u_info is not None:
            u_info.avaurl =  common.getavaurl(u_info.avaurl)
        return u_info
    @staticmethod
    def getadmininfo(uid):  # 获取指定id 管理员信息
        #.exclude('password_hash') 不包含字段
        query = Q(_id=uid) & (Q(role_id=1) | Q(role_id__gte=4))
        return User.objects(query).only('name').first()

    @staticmethod
    def getlist_geo_map(x, y,count=10, max=1000,roid=2):
    	#根据坐标获取数据列表 max最大距离(米)
        return User.objects(geo__near=[x, y],geo__max_distance=max,role_id=roid,state=1)

    @staticmethod
    def getlist_geo_list(x, y,industryid=0,count=10, max=1000):
    	#根据坐标获取数据列表 max最大距离(米)
    	query = Q(geo__near=[x, y]) & Q(geo__max_distance=max) &Q(role_id=2) & Q(state=1)
    	if industryid>0:
    		query = query & Q(industryid=industryid)
        list_count = User.objects(query).count()
        if list_count>=count:
            rand = common.getrandom()
            relist = []
            u_list = User.objects(query & Q(stats__rand__gte=rand))#大于等于  )|Q(_id__gte=rand)
            for item in u_list:
		        relist.append(item)
            if len(u_list)<count:
                ul_list = User.objects(query & Q(stats__rand__lte=rand))#小于等于 |Q(_id__lte=rand)
                for item in ul_list:
		        	relist.append(item)

            return relist
        else:
            return User.objects(query)

    @staticmethod
    def isusername(username):
		#查找帐号是否存在 >0 存在   =0 不存在
		if len(username)>0:
			return User.objects(username=username).count()
		else:
			return -1

    def useredit(self):
        # 更新个人信息(用户)
        if self._id > 0:
            #print str(self._id)
            update = {}
            if len(self.name) > 0:
                update['set__name'] = self.name
            if self.sex>-1:
                update['set__sex'] = self.sex
            if len(self.avaurl)>0:
                update['set__avaurl'] = self.avaurl
            if self.role_id==2 or self.role_id==1:
                if self.domainid>-1:
                    update['set__domainid'] = self.domainid
                if self.industryid>-1:
                    update['set__industryid'] = self.industryid
            update['set__stats__lastaction'] = common.getstamp()
            User.objects(_id=self._id).update_one(**update)

            if self.role_id==2:
                u_info = User.objects(_id=self._id).first()
                User.Create_Q_YUNSOU_DATA(u_info)

    @staticmethod
    def updatestate(uid,state):
        #更新用户状态 -2 -> 1
        update = {}
        update['set__state'] = state
        User.objects(_id=uid).update_one(**update)

    @staticmethod
    def updatephone(uid,newphone):
        #更新手机号
        #if g.current_user is not None:
        #    if g.current_user._id > 0:
        update = {}
        update['set__username'] = newphone
        User.objects(_id=uid).update_one(**update)
        return 1
        #return 0

    def updateforgetpaw(self):
        #忘记密码
        update = {}
        if len(self.password_hash) > 0:
            self.password = self.password_hash
            update['set__password_hash'] = self.password_hash
            User.objects(username=self.username).update_one(**update)
            return 1
        else:
            return 0

    @staticmethod
    def updatemoney(uid,money):
        #充值金额更新
        update = {}
        update['inc__money'] = money
        User.objects(_id=uid).update_one(**update)

    def updatebindphone(self):
        #更新第三方登录 绑定手机号 - 用户
        update = {}
        if len(self.username) > 0:
            update['set__username'] = self.username
        if len(self.password_hash) > 0:
            self.password = self.password_hash
            update['set__password_hash'] = self.password_hash
        User.objects(_id=self._id).update_one(**update)

    @staticmethod
    def updatecontact(uid,_type,val):
        #更新联系方式 微信 QQ (所有会员)
        update = {}
        if _type==1:
            update['set__weixin'] = val
        else:
            update['set__qq'] = val
        User.objects(_id=uid).update_one(**update)
        return 1


    @staticmethod
    def snslogin(sns,uid):
        query = None
        if sns==1:
            query=Q(sns__sina=uid)
        elif sns==2:
            query=Q(sns__qq=uid)
        elif sns==3:
            query=Q(sns__weixin=uid)
        return User.objects(query).first()

    def saveinfo_snslogin(self):
        if self.username == '-1':
            self.username = 'sina_'+str(self._id)
        elif self.username == '-2':
            self.username = 'qq_'+str(self._id)
        elif self.username == '-3':
            self.username = 'weixin_'+str(self._id)
        elif len(self.username)==0:
            if self.role_id==2:
                self.username = 'zj_'+str(self._id)
            elif self.role_id==3:
                self.username = 'pt_'+str(self._id)

        self.password = self.password_hash
        self.date = common.getstamp()
        self.save()

    def saveinfo(self):
        self._id = collection.get_next_id(self.__tablename__)

        if self.username == '-1':
            self.username = 'sina_'+str(self._id)
        elif self.username == '-2':
            self.username = 'qq_'+str(self._id)
        elif self.username == '-3':
            self.username = 'weixin_'+str(self._id)

        self.password = self.password_hash
        self.date = common.getstamp()
        self.save()

        return self._id

    def saveinfo_app(self):
        #前端注册用户信息
        
        if len(self.username)==0:
                if self.role_id==2:
                    self.username = 'zj_'+str(self._id)
                elif self.role_id==3:
                    self.username = 'pt_'+str(self._id)
        istrue = User.isusername(username=self.username)
        if istrue == 0:
            self.password = self.password_hash
            self.date = common.getstamp()
            self.save()

            return self._id
        else:
            return -1

    def editinfo(self):
    	#后台更新用户信息
        if self._id > 0:
            update = {}
            # update.append({'set__email': self.email})
            update['set__role_id'] = self.role_id
            if len(self.email) > 0:
                update['set__email'] = self.email
            if len(self.username) > 0:
                update['set__username'] = self.username
            if len(self.name) > 0:
                update['set__name'] = self.name
            print self.password_hash
            if len(self.password_hash) > 0:
                self.password = self.password_hash
                update['set__password_hash'] = self.password_hash
            print self.password_hash
            update['set__confirmed'] = self.confirmed
            update['set__domainid'] = self.domainid
            update['set__industryid'] = self.industryid
            update['set__sex'] = self.sex
            update['set__job'] = self.job
            update['set__geo'] = self.geo
            update['set__intro'] = self.intro
            update['set__content'] = self.content
            update['set__bgurl'] = self.bgurl
            update['set__fileurl'] = self.fileurl
            update['set__avaurl'] = self.avaurl
            update['set__label'] = self.label
            update['set__workexp'] = self.workexp
            update['set__edu'] = self.edu
            update['set__openplatform'] = self.openplatform

            update['set__stats__lastaction'] = common.getstamp()
            '''
            update['set__stats__baidu'] = self.stats.baidu
            update['set__stats__weixin'] = self.stats.weixin
            update['set__stats__zhihu'] = self.stats.zhihu
            update['set__stats__sina'] = self.stats.sina
            update['set__stats__twitter'] = self.stats.twitter
            update['set__stats__facebook'] = self.stats.facebook
            update['set__stats__github'] = self.stats.github

            update['set__stats__baiduurl'] = self.stats.baiduurl
            update['set__stats__weixinurl'] = self.stats.weixinurl
            update['set__stats__zhihuurl'] = self.stats.zhihuurl
            update['set__stats__sinaurl'] = self.stats.sinaurl
            update['set__stats__twitterurl'] = self.stats.twitterurl
            update['set__stats__facebookurl'] = self.stats.facebookurl
            update['set__stats__githuburl'] = self.stats.githuburl
            '''
            update['set__state'] = self.state
            update['set__sort'] = self.sort
            User.objects(_id=self._id).update_one(**update)

            if self.role_id==2:
                User.Create_Q_YUNSOU_DATA(self)
            '''
            #更新whoosh
            updata_whoosh = {}
            updata_whoosh['_id']=self._id
            updata_whoosh['n']=unicode(self.name)
            updata_whoosh['l']=self.label
            updata_whoosh['j']=self.job
            searchwhoosh.update(updata_whoosh)
            '''
            logmsg = '编辑'+(self.role_id==2 and '用户'or '专家')+'-'+str(self._id)+'-'+self.name +'-' + self.job
            Log.saveinfo(remark=logmsg)

            return 1
        else:

            self._id = collection.get_next_id(self.__tablename__)
            if len(self.username)==0:
                    if self.role_id==2:
                        self.username = 'zj_'+str(self._id)
                    elif self.role_id==3:
                        self.username = 'pt_'+str(self._id)
            istrue = User.isusername(username=self.username)
            if istrue == 0:
                self.password = self.password_hash
                self.date = common.getstamp()
                self.save()

                '''
                #更新whoosh
                updata_whoosh = {}
                updata_whoosh['_id']= self._id
                updata_whoosh['n']= unicode(self.name)
                updata_whoosh['j']= unicode(self.job)
                updata_whoosh['l']=self.label
                searchwhoosh.update(updata_whoosh)
                '''
                logmsg = '创建'+(self.role_id==2 and '用户'or '专家')+'-'+str(self._id)+'-'+self.name +'-' + self.job
                Log.saveinfo(remark=logmsg)

                return self._id
            else:
                return -1

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASK_ADMIN']:
                self.role = Role.objects(permissions=0xff).first()
            if self.role is None:
                self.role = Role.objects(default=True).first()
        '''
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()
        '''
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password

        update = {}
        update['set__password_hash'] = self.password_hash
        update['set__stats__lastaction'] = common.getstamp()
        User.objects(_id=self._id).update_one(**update)

        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})
    '''

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        # db.session.add(self)
        return True

    def can(self, permissions):
        return self.role is not None and
            (self.role.permissions & permissions) == permissions
    '''

    def can(self,name, permissions):
        #return self.role is not None and (getattr(self.role['permissions'],name) & permissions) == permissions
        return self.role is not None and (self.role['permissions'][name] & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)
    '''

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
    '''

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def to_json(self, type=0):  # type 0默认 1简短 2... 3...
        if type == -1:
            #专家详情
            json_user = {
                '_id': self.id,
                'name': self.name.encode('utf-8'),
                'sex': self.sex,
                'job': self.job.encode('utf-8'),
                'auth': {'expert': self.auth.expert,'expertprocess': self.auth.expertprocess},  # self.auth.vip
                'grade': common.getgrade(self.stats.comment_count, self.stats.comment_total),
                'meet_c': self.stats.meet,
                'follow':[item.to_json() for item in self.openplatform],
                #'follow':[{'baidu':self.stats.baidu,'baiduurl':self.stats.baiduurl},{'weixin':self.stats.weixin,'weixinurl':self.stats.weixinurl},{'zhihu':self.stats.zhihu,'zhihuurl':self.stats.zhihuurl},{'sina':self.stats.sina,'sinaurl':self.stats.sinaurl},{'twitter':self.stats.twitter,'twitterurl':self.stats.twitterurl},{'facebook':self.stats.facebook,'facebookurl':self.stats.facebookurl},{'github':self.stats.github,'githuburl':self.stats.githuburl}],
                # [39.9442, 116.324]
                'geo': [self.geo['coordinates'][1], self.geo['coordinates'][0]],
                'intro': self.intro.encode('utf-8'),
                'content': self.content.encode('utf-8'),
                'bgurl': self.bgurl.encode('utf-8'),
                'fileurl': self.fileurl.encode('utf-8'),
                'avaurl': common.getavaurl(self.avaurl),#common.getavatar(userid=self.id)
                'work': [item.to_json() for item in self.workexp],
                'edu': [item.to_json() for item in self.edu],
                'label':self.label,
                'role_id':self.role_id,
                'domainid':self.domainid,
                'industryid':self.industryid,
                'phone':self.username
            }
        elif type == 0:
            #普通用户
            json_user = {
                '_id': self.id,
                'name': self.name.encode('utf-8'),
                'sex': self.sex,
                'job': self.job.encode('utf-8'),
                'auth': {'becomeexpert': self.auth.becomeexpert,'expertprocess': self.auth.expertprocess}, # self.auth.vip
                'grade': common.getgrade(self.stats.comment_count, self.stats.comment_total),
                'meet_c': self.stats.meet,
                # [39.9442, 116.324]
                'geo': [self.geo['coordinates'][1], self.geo['coordinates'][0]],
                'intro': self.intro.encode('utf-8'),
                'fileurl': self.fileurl.encode('utf-8'),
                'avaurl': common.getavaurl(self.avaurl),#common.getavatar(userid=self.id)
                'work': [item.to_json() for item in self.workexp],
                'edu': [item.to_json() for item in self.edu],
                'label':self.label,
                'role_id':self.role_id,
                'domainid':self.domainid,
                'industryid':self.industryid,
                'money':self.money,
                'apptime':self.apptime,
                'calltime':self.calltime,
                'wish':self.wish,
                'calltype':(self.apptype&0x01)==0x01 and 1 or 0, #通话模式开启
                'meettype':(self.apptype&0x02)==0x02 and 1 or 0, #见面模式开启
                'phone':self.username,
                'weixin':self.weixin,
                'qq':self.qq,
                'email':self.email,
                'rong_token':self.rong_token
            }
        elif type == 1:
            json_user = {
                '_id': self.id,
                'name': self.name.encode('utf-8'),
                'avaurl': common.getavaurl(self.avaurl)
            }
        elif type == 2:
            json_user = {
                '_id': self.id,
                'name': self.name.encode('utf-8'),
                'intro': self.intro.encode('utf-8'),
                'job': self.job.encode('utf-8'),
                'avaurl': common.getavaurl(self.avaurl)
            }
        elif type == 3:
            json_user = {
                '_id': self.id,
                'name': self.name.encode('utf-8'),
                'job': self.job.encode('utf-8'),
                'avaurl': common.getavaurl(self.avaurl)
            }
        elif type == 4:
            json_user = {
                '_id': self.id,
                'name': self.name.encode('utf-8'),
                'job': self.job.encode('utf-8'),
                'avaurl': common.getavaurl(self.avaurl),
                'grade': common.getgrade(self.stats.comment_count, self.stats.comment_total),
                'auth': {'vip': 1},
                'stats': self.stats.to_json(),
                'sex': self.sex
            }
        elif type == 5:
            json_user = {
                '_id': self.id,
                'name': self.name.encode('utf-8'),
                'job': self.job.encode('utf-8'),
                'avaurl': common.getavaurl(self.avaurl),
                'grade': common.getgrade(self.stats.comment_count, self.stats.comment_total),
                'auth': {'vip': 1}
            }
        elif type == 6:
        	#地图专家列表
            json_user = {
                '_id': self.id,
                'name': self.name.encode('utf-8'),
                'job': self.job.encode('utf-8'),
                'geo': [self.geo['coordinates'][1], self.geo['coordinates'][0]],
                'avaurl': common.getavaurl(self.avaurl),
                'grade': common.getgrade(self.stats.comment_count, self.stats.comment_total),
                'auth': {'vip': 1}
            }

        return json_user

    def generate_auth_token(self, expiration):
        #s = URLSafeSerializer(current_app.config['SECRET_KEY'], salt=current_app.config['SECRET_SALT'])
        s = Serializer(current_app.config['SECRET_KEY'],expires_in=expiration)
        return s.dumps({'id': self.id}, salt=current_app.config['SECRET_SALT']).decode('ascii')

    @staticmethod
    def verify_auth_token(token):
        # token =
        # 'eyJhbGciOiJIUzI1NiIsImV4cCI6MTQzMzkzMDUwNiwiaWF0IjoxNDMzOTI2OTA2fQ.eyJpZCI6NH0.kf4L_xi-7vF655_g6-y7XgajANtzkPsFVnxYDp8g0ZY'
        #s = URLSafeSerializer(current_app.config['SECRET_KEY'], salt=current_app.config['SECRET_SALT'])
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, salt=current_app.config['SECRET_SALT'])
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        return User.objects().get(_id=data['id'])

    def __repr__(self):
        return '<User %r>' % self.username

class AnonymousUser(AnonymousUserMixin):

    confirmed=True #允许访问公共api

    def can(self, permissions):
        return False

    def is_administrator(self):
        return False # 游客

login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.objects(id=user_id).first()


class collection(db.Document):
    meta = {
        'collection': 'collection',
    }
    name = db.StringField(max_length=30, required=True)
    index = db.IntField(required=True)

    @staticmethod
    def get_next_id(tablename):
        doc = collection.objects(name=tablename).modify(inc__index=1)
        if doc:
            return doc.index + 1
        else:
            collection(name=tablename, index=1).save()
            return 1 # 自增id


class Ad(db.Document):  # 广告
    __tablename__ = 'ad'
    meta = {
        'collection': __tablename__,
    }
    _id = db.IntField(primary_key=True)
    title = db.StringField(
        default='', max_length=64, required=True, db_field='t')
    group_id = db.IntField(default=0, required=True, db_field='g')  # 分组id 0未分组 1清单 
    fileurl = db.StringField(default='', db_field='fu')  # 文件地址
    url = db.StringField(db_field='u')  # 跳转地址或 跳转id
    sort = db.IntField(default=0, db_field='s')  # 排序

    @staticmethod
    def getlist_app(gid=0,index=1, count=10):
        pageindex =(index-1)*count
        sort='sort'
        if gid is 0:
            return Ad.objects.order_by(sort).skip(pageindex).limit(count)
        else:
            return Ad.objects(group_id=gid).order_by(sort).skip(pageindex).limit(count)

    @staticmethod
    def getlist(gid=0,index=1, count=10):
        pageindex =(index-1)*count

        if gid == 0:
            return Ad.objects.order_by("-_id").skip(pageindex).limit(count)
        else:
            return Ad.objects(group_id=gid).order_by("-_id").skip(pageindex).limit(count)

    @staticmethod
    def getcount(gid=0):
        if gid == 0:
            return Ad.objects.count()
        else:
            return Ad.objects(group_id=gid).count()

    @staticmethod
    def getinfo(aid):
        return Ad.objects.get(_id=aid)

    def editinfo(self):
        if self._id > 0:
            update = {}
            if len(self.title) > 0:
                update['set__title'] = self.title

            update['set__group_id'] = self.group_id
            update['set__fileurl'] = self.fileurl
            update['set__url'] = self.url
            update['set__sort'] = self.sort
            Ad.objects(_id=self._id).update_one(**update)

            logmsg = '编辑广告-'+str(self._id)+'-'+self.title
            Log.saveinfo(remark=logmsg)
            return 1
        else:
            self._id = collection.get_next_id(self.__tablename__)
            self.save()
            logmsg = '创建广告-'+str(self._id)+'-'+self.title
            Log.saveinfo(remark=logmsg)
            return self._id

    @staticmethod
    def delinfo(aid):
        Ad.objects(_id=aid).delete()

    def to_json(self):
        json_ad = {
            '_id': self.id,
            'title': self.title.encode('utf-8'),
            'fileurl': self.fileurl.encode('utf-8'),
            'url': self.url.encode('utf-8'),
            'sort': self.sort,
        }
        return json_ad

class Log(db.Document):  
    # 管理员日志
    __tablename__ = 'log'
    meta = {
        'collection': __tablename__,
    }
    _id = db.IntField(primary_key=True)
    remark = db.StringField(default='', db_field='r')  # 备注
    date = db.IntField(default=common.getstamp(), db_field='d')  # 创建时间
    admin_id = db.IntField(default=0, db_field='a')  # 管理员ID

    @staticmethod
    def saveinfo(remark='',aid=0):
        Log(remark=remark,admin_id=aid==0 and g.current_user._id or aid,_id=collection.get_next_id(Log.__tablename__),date=common.getstamp()).save()

    @staticmethod
    def getlist(aid=0,index=1, count=10):
    	# 获取列表 0全部  -1官方  -2专家
        pageindex =(index-1)*count
        if aid == 0:
            return Log.objects.order_by("-_id").skip(pageindex).limit(count)
        else:
            return Log.objects(admin_id=aid).order_by("-_id").skip(pageindex).limit(count)

    @staticmethod
    def getcount(aid=0):
    	if aid == 0:
            return Log.objects.count()
        else:
            return Log.objects(admin_id=aid).count()

class Message(db.Document):  
    # 消息
    __tablename__ = 'message'
    meta = {
        'collection': __tablename__,
    }
    _id = db.IntField(primary_key=True)
    user_id = db.IntField(default=0, db_field='u')  # 用户id
    appointment_id = db.IntField(default=0, db_field='a')  # 预约订单id
    date = db.IntField(default=0, db_field='d')  # 创建时间
    type = db.IntField(default=0, db_field='ty')  # 消息类型 1成功 2失败 3温馨提醒 4消息提醒
    title = db.StringField(default='', db_field='t')  # 标题
    content = db.StringField(default='', db_field='c')  # 内容

    def saveinfo(self):
        self._id = collection.get_next_id(self.__tablename__)
        self.date = common.getstamp()
        self.save()

    @staticmethod
    def getlist(uid,index=1, count=10):
        pageindex =(index-1)*count
        return Message.objects(user_id=uid).order_by("-_id").skip(pageindex).limit(count)

    def to_json(self):
        json_message = {
            '_id': self.id,
            'title': self.title.encode('utf-8'),
            'content': self.content.encode('utf-8'),
            'appointment_id': self.appointment_id,
            'date': self.date,
            'type': self.type
        }
        return json_message

class PayLog(db.Document):  
    # 充值日志
    __tablename__ = 'paylog'
    meta = {
        'collection': __tablename__,
    }
    _id = db.IntField(primary_key=True)
    created = db.IntField(default=0, db_field='c') 
    paid = db.BooleanField(default=False, db_field='p')
    app =  db.StringField(default='', db_field='a')
    channel =  db.StringField(default='', db_field='ch')
    order_no =  db.StringField(default='', db_field='o')
    #client_ip
    amount =  db.IntField(default='', db_field='am')
    amount_settle =  db.IntField(default='', db_field='ams')
    currency =  db.StringField(default='', db_field='cu')
    subject =  db.StringField(default='', db_field='s')
    body =  db.StringField(default='', db_field='b')
    time_paid =  db.IntField(default='', db_field='t')  # 支付成功时间
    time_expire =  db.IntField(default='', db_field='te')
    transaction_no =  db.StringField(default='', db_field='tr')
    amount_refunded =  db.IntField(default=0, db_field='ar')
    failure_code =  db.StringField(default='', db_field='f')
    failure_msg =  db.StringField(default='', db_field='fa')
    description =  db.StringField(default='', db_field='d')

    def saveinfo(self):
        self._id = collection.get_next_id(self.__tablename__)
        self.save()
