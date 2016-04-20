#!/usr/bin/env python
#-*- coding: utf-8 -*-
from ..core import wxpayapi, common
from ..models import Permission, Role, User, UserStats, collection,\
    Topic, Comment, Ad
#from .. import searchwhoosh

def iniuserformat():  # 修复字段结构
    for item in User.getlist():
        User.objects(_id=item._id).update_one(
            set__fileurl='http://img1.cache.netease.com/ent/2015/6/23/2015062310025857add.jpg')


def addad():
    for i in range(1, 10):
        item1 = Ad()
        item1.id = collection.get_next_id('ad')
        item1.title = str(i) + '广告展示'
        item1.group_id = 0
        item1.url = '40'
        item1.fileurl = 'http://img4.cache.netease.com/photo/0026/2015-06-25/900x600_ASVMA6GL43AJ0026.jpg'
        item1.save()

def ini_users_whoosh():
    searchwhoosh.rebuild_index()
