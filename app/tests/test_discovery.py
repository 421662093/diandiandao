#!/usr/bin/env python
#-*- coding: utf-8 -*-
from ..core import wxpayapi, common
from ..models import Permission, collection, Topic, Inventory, InvTopic


def iniinv(userid=0):

    for i in range(1, 5):
        it1 = Inventory()
        it1.id = collection.get_next_id('inventory')
        #it1.user_id = userid
        it1.title = '我们在主模块里面定义了一个' + str(i)
        it1.sort = 0
        for i in range(1, 5):
            item2 = InvTopic()
            item2._id = collection.get_next_id('invtopic')
            item2.title = '创业者需要的服务' + str(i)
            item2.content = '上用户言论只代表其个人观点，不代表CSDN网站的观上用户言论只代表其个人观点，不代表CSDN网站的观'
            item2.expert = [50, 41, 43, 42, 37, 36, 39]
            item2.sort = 4
            it1.topic.append(item2)
        it1.save()


def initopicformat():  # 修复字段结构

    Inventory.objects().update(
        **{'set__topic__$__expert': [12, 13, 15, 16, 17]})
    #Inventory.objects().update(set__topic__0__expert=[12, 13, 15, 16, 17])
    # for item in Topic.getlist():
    #    Topic.objects(_id=item._id).update_one(
    #        set__content='这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容这是一段内容。')
