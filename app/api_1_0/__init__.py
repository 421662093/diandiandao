#-*- coding: utf-8 -*-
'''
推送
    type = update_appointment 更新订单状态
        app_id -- 订单号
        state -- 订单状态

    type = recharge 充值
        state -- 充值状态 1成功

    type = viewapp 查看订单
        app_id -- 订单号
'''
from flask import Blueprint

api = Blueprint('api', __name__)

from . import authentication