#!/usr/bin/env python
#-*- coding: utf-8 -*-
from ..core import wxpayapi, common
import uuid
from ..models import Permission,RolePermissions, Role, User, UserStats, collection,\
    Topic, Comment, WorkExp, Edu, Appointment


def updateuser(uid=0):
    for item in User.getlist():
        we = []
        weitem = WorkExp()
        weitem.start = common.time2stamp(_time='2012-5-10', _type='%Y-%m-%d')
        weitem.end = common.time2stamp(_time='2014-5-10', _type='%Y-%m-%d')
        weitem.name = '北京扶摇直上信息科技有限公司'
        weitem.job = '技术总监'
        weitem.intro = '总技术负责移动终端研发'
        we.append(weitem)
        weitem2 = WorkExp()
        weitem2.start = common.time2stamp(_time='2014-6-10', _type='%Y-%m-%d')
        weitem2.end = common.time2stamp(_time='2015-10-10', _type='%Y-%m-%d')
        weitem2.name = '北京万达科技有限公司'
        weitem2.job = '运营总监'
        weitem2.intro = '总技术负责移动终端研发'
        we.append(weitem2)

        edu = []
        eduitem1 = Edu()
        eduitem1.start = common.time2stamp(_time='2012-5-10', _type='%Y-%m-%d')
        eduitem1.end = common.time2stamp(_time='2013-5-10', _type='%Y-%m-%d')
        eduitem1.name = '北京大学附中'
        eduitem1.dip = '初中'
        eduitem1.mador = ''
        edu.append(eduitem1)
        eduitem2 = Edu()
        eduitem2.start = common.time2stamp(_time='2013-5-10', _type='%Y-%m-%d')
        eduitem2.end = common.time2stamp(_time='2015-6-10', _type='%Y-%m-%d')
        eduitem2.name = '北京大学'
        eduitem2.dip = '本科'
        eduitem2.mador = '计算机网络'
        edu.append(eduitem2)

        update = {}
        update['set__workexp'] = we
        update['set__edu'] = edu
        User.objects(_id=item._id).update_one(**update)


def iniuserformat():  # 修复字段结构
    #User.objects().update(unset__workexp__S__intro=1)
    #User.objects.update(set__thinktank=[21,22,23,24])

    '''
    update = {}
    update['set__stats'] = UserStats()
    for item in User.getlist():
        User.objects(_id=item._id).update_one(**update)
    '''
    #User.objects.update(set__state=1)

def iniroleformat():  # 修复字段结构
    User.objects.update(set__label=[])
    Role.objects.update(set__permissions=RolePermissions())
def adduser():
    # for i in range(1, 10):
    i = 1000
    col1 = User()
    #col1.id = collection.get_next_id('users')
    col1.email = str(i) + '@qq.com'
    col1.name = u'郭德纲'
    col1.username = str(i) + 'clr'
    col1.password = '123456'
    col1.job = u'python工程师'
    col1.confirmed = 1
    col1.geo = [28.321321, 23.4334234]
    col1.stats = UserStats()
    col1.intro = '我就是传说中的大神'
    col1.fileurl = 'http://img1.cache.netease.com/ent/2015/6/23/2015062310025857add.jpg'
    we = []
    weitem = WorkExp()
    weitem.start = common.time2stamp(_time='2012-5-10', _type='%Y-%m-%d')
    weitem.end = common.time2stamp(_time='2014-5-10', _type='%Y-%m-%d')
    weitem.name = '北京扶摇直上信息科技有限公司'
    weitem.job = '技术总监'
    weitem.intro = '总技术负责移动终端研发'
    we.append(weitem)
    weitem2 = WorkExp()
    weitem2.start = common.time2stamp(_time='2014-6-10', _type='%Y-%m-%d')
    weitem2.end = common.time2stamp(_time='2015-10-10', _type='%Y-%m-%d')
    weitem2.name = '北京万达科技有限公司'
    weitem2.job = '运营总监'
    weitem2.intro = '总技术负责移动终端研发'
    we.append(weitem2)

    edu = []
    eduitem1 = Edu()
    eduitem1.start = common.time2stamp(_time='2012-5-10', _type='%Y-%m-%d')
    eduitem1.end = common.time2stamp(_time='2013-5-10', _type='%Y-%m-%d')
    eduitem1.name = '北京大学附中'
    eduitem1.dip = '初中'
    eduitem1.mador = ''
    edu.append(eduitem1)
    eduitem2 = Edu()
    eduitem2.start = common.time2stamp(_time='2013-5-10', _type='%Y-%m-%d')
    eduitem2.end = common.time2stamp(_time='2015-6-10', _type='%Y-%m-%d')
    eduitem2.name = '北京大学'
    eduitem2.dip = '本科'
    eduitem2.mador = '计算机网络'
    edu.append(eduitem2)
    col1.workexp = we
    col1.edu = edu
    col1.edituser()


def addappointment():
    app = Appointment()
    app._id = Appointment.createid()
    app.user_id = 53
    app.appid = 35
    app.topic_title = '加速会【GUSHI】创业公司新媒体运营联盟'
    app.topic_id = 50
    app.appdate = common.getstamp()
    app.apptype = 1
    app.address = '北京市西城区新街口北大街74号剧空间剧场(近北京科学教育电影制片厂院内)'
    app.price = 1000
    app.attachment = ['img.png']
    app.remark = '新媒体运营小编为何没有出路？ 新媒体运营到底归属于哪个山头？'
    app.state = 0
    app.paystate = 0
    app.save()
