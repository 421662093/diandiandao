# coding:utf-8

from flask import make_response
import json
import time
import cgi
import HTMLParser
import random
from config import config
import datetime
from .. import conf


# 自定义jsonify 解决flask.jsonify无法返回中文
def jsonify(status=200, indent=4, sort_keys=True, **kwargs):
    response = make_response(
        json.dumps(dict(**kwargs), ensure_ascii=False, indent=indent, sort_keys=sort_keys))
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['mimetype'] = 'application/json'
    response.status_code = status
    return response


def stamp2time(stamp, _type='%Y-%m-%d %H:%M:%S'):  # 将时间戳转化为时间
        # time.gmtime(_time)
    return time.strftime(_type, time.localtime(stamp+28800))


def time2stamp(_time, _type='%Y-%m-%d %H:%M:%S'):  # 将时间转化为时间戳

    return time.mktime(time.strptime(_time, _type))

def getdaystamp():  # 获取当前时间戳
    import datetime
    today = datetime.date.today()
    return time2stamp(str(today.year)+'-'+str(today.month)+'-'+str(today.day),'%Y-%m-%d')

def getstamp():  # 获取当前时间戳
    return time.time()


def getavatar(isa=1, userid=0, _type=1):  # 获取用户头像地址

    if isa == 1:
        return getavatar(userid, _type)
    else:
        if _type == 1:
            return "http://ava.fanka.me/noavatar_small.gif"
        elif _type == 2:
            return "http://ava.fanka.me/noavatar_middle.gif"
        else:
            return "http://ava.fanka.me/noavatar_big.gif"


def getavatar(userid=0, _type=1):
	# 获取用户头像地址
    return 'http://182.254.221.13:8080/static/img/expert1%20@2x.png'
    houzhui = ".jpg"
    avapath = "/data/avatar"

    # if _type > 0:
    # avapath = AvaImgDomain
    if _type == 1:
        houzhui = "_small.jpg"
    elif _type == 2:
        houzhui = "_middle.jpg"
    elif _type == 3 | _type == -1:
        houzhui = "_big.jpg"

    return getuserpath(userid,avapath,houzhui)

def getuserpath(userid=0,avapath=conf.UPLOAD_FOLDER+'/user',houzhui=''):  
	# 获取用户上传路径

    numbers = []
    userid = str(userid)

    for i in range(0, len(userid)):
        numbers.append(str(userid[i]))
    numlen = len(numbers)
    if numlen < 3:
        if numlen == 1:
            return avapath + "/000/00/00/0" + numbers[0] + houzhui
        else:
            return avapath + "/000/00/00/" + numbers[0] + numbers[1] + houzhui
    elif numlen < 5:
        if numlen == 3:
            return avapath + "/000/00/0" + numbers[0] + "/" + numbers[1] + numbers[2] + houzhui
        else:
            return avapath + "/000/00/" + numbers[0] + numbers[1] + "/" + numbers[2] + numbers[3] + houzhui
    elif numlen < 7:
        if numlen == 5:
            return avapath + "/000/0" + numbers[0] + "/" + numbers[1] + numbers[2] + "/" + numbers[3] + numbers[4] + houzhui
        else:
            return avapath + "/000/" + numbers[0] + numbers[1] + "/" + numbers[2] + numbers[3] + "/" + numbers[4] + numbers[5] + houzhui
    else:
        if numlen == 7:
            return avapath + "/00" + numbers[0] + "/" + numbers[1] + numbers[2] + "/" + numbers[3] + numbers[4] + "/" + numbers[5] + numbers[6] + houzhui
        elif numlen == 8:
            return avapath + "/0" + numbers[0] + numbers[1] + "/" + numbers[2] + numbers[3] + "/" + numbers[4] + numbers[5] + "/" + numbers[6] + numbers[7] + houzhui
        else:
            return avapath + "/" + numbers[0] + numbers[1] + numbers[2] + "/" + numbers[3] + numbers[4] + "/" + numbers[5] + numbers[6] + "/" + numbers[7] + numbers[8] + houzhui

def htmlescape(string):  # html编码
    return cgi.escape(string)


def htmlunescape(string):  # html反编码
    html_parser = HTMLParser.HTMLParser()
    return html_parser.unescape(string)


def getgrade(count, total):  # 计算评级 总人数，总分数
    gra = 5  # 每人5分
    if count > 0 and total > 0:
        tmp = float(total) / (float(gra) * count) * 100
        return int(tmp / 20) + 1
    else:
        return gra


def getpagecount(count, pagesize):  # 获取页码数
    return (count + pagesize - 1) / pagesize

def can(permissions,permissionsmin):
    #判断主权限是否包含min权限
    if len(str(permissions))==0:
        permissions = 0
    return (permissions & permissionsmin) == permissionsmin

def getdomain(did):
    #获取领域名
    return conf.DOMAIN[did]

def getindustry(iid):
    #获取行业名
    return conf.INDUSTRY[iid]

def getrole(rolelist,rid):
    #获取角色信息
    listlen = len(rolelist)
    for v in xrange(0,listlen):
    	if v>0 and v<listlen:
    		print rolelist[v]
    return None

def getrandom(start=1000,end=1000000):
    #生成随机数
    return random.randint(start, end) 

def delrepeat(templist):
    #移除list重复
    new_ids = []
    for item in templist:
        if item not in new_ids and len(item)>0:
            new_ids.append(item)
    return new_ids

def allowed_file(filename):
	#判断上传文件是否允许
	return '.' in filename and filename.rsplit('.', 1)[1] in conf.ALLOWED_EXTENSIONS

def getuserstate(state):
    #获取会员状态信息
    #if state==-1:
    #    return '新建'
    if state==-2:
        return '待审核'
    elif state==1:
        return '正常'
    else:
        return '暂停'

def gettopicstate(state):
    #获取话题状态信息
    #if state==-1:
    #    return '新建'
    if state==0:
        return '待审核'
    elif state==1:
        return '正常'
    else:
        return '已删除'

def getexpertauthstate(state):
    #获取认证专家状态
    if state==0:
        return '待审核'
    elif state==1:
        return '已审核'
    else:
        return '已删除'

def getadgroupname(gid):
    #获取广告分组名  1首页顶部广告(清单)
    if gid==1:
        return '发现顶部图片(清单)'
    else:
        return '未分组'

def getappointmentid(uid):
	# 构建预约id
    today = datetime.date.today()
    trand = 0;
    val = 10;
    length = 10 - len("%d"%uid)-1
    for item in xrange(1,length):
    	val = val * 10
    trand = getrandom(val,val*10-1);
    return '15'+str(today.day)+str(trand)+str(uid)+ str(getrandom(10,99))
	#string tid = trand.ToString() + info.SID + trand2.ToString()+Tools.GetRandom(6);

def getavaurl(url):
    # 无头像 返回默认头像
    if len(url)==0:
        return conf.DEFAULT_AVATAR
    return url

def strtoint(val,default):
    # 字符串转数字
    try:
        num = int(val)
        return num
    except Exception, e:
        return default

def getopenplatform(_list,name):
    # 用户开放平台 根据name 返回地址
    for item in _list:
        if item.name==name:
            return item.url
    return ''