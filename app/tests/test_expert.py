#!/usr/bin/env python
#-*- coding: utf-8 -*-
from ..core import wxpayapi, common
from ..models import Permission, Role, User, UserStats, collection, Topic, TopicPay, Comment,TopicStats,TopicConfig


def initopic(userid=28):
    for i in range(1, 5):
        col1 = Topic()
        col1.id = collection.get_next_id('topics')
        col1.user_id = userid
        col1.title = '我们在主模块里面定义了一个'
        col1.intro = '以上用户言论只代表其个人观点，不代表CSDN网站的观点或立场'
        col1.content = '以上用户言论只代表其个人观点，不代表CSDN网站的观言论只代表其个人观点，不代表CSDN网站的言论只代表其个人观点，不代表CSDN网站的言论只代表其个人观点，不代表CSDN网站的言论只代表其个人观点，不代表CSDN网站的点或立场'
        col1.pay = TopicPay()
        col1.save()
        for i in range(1, 5):
            col2 = Comment()
            col2.id = collection.get_next_id('comments')
            col2.user_id = 15
            col2.name = '飞鸽'
            col2.top_id = col1.id
            col2.top_title = '以上用户言论只代表其个立场'
            col2.conetnt = '上用户言论只代表其个人观点，不代表CSDN网站的观上用户言论只代表其个人观点，不代表CSDN网站的观'
            col2.grade = 4
            col2.save()

def inicommons():

        for i in range(1, 5):
            col2 = Comment()
            col2.id = collection.get_next_id('comments')
            col2.user_id = 11
            col2.name = '飞鸽'
            col2.top_id = 50
            col2.top_title = '以上用户言论只代表其个立场'
            col2.content = '上用户言论只代表其个人观点，不代表CSDN网站的观上用户言论只代表其个人观点，不代表CSDN网站的观'
            col2.grade = 4
            col2.save()

def initopicformat():  # 修复字段结构
    update = {}
    update['set__state'] = 1
    Topic.objects().update(**update)
    #Topic.objects().update({'set__expert': [12, 13, 15, 16, 17]})
    # Topic.objects().update({'unset__g'})

    # Topic.objects().update(
    #   set__pay={'call': 0, 'meet': 0})
