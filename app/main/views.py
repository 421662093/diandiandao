#!/usr/bin/env python
#-*- coding: utf-8 -*-
from flask import render_template, redirect, url_for, abort, flash, request,\
    current_app, make_response
from flask.ext.login import login_required, current_user
from ..decorators import admin_required, permission_required
'''
from flask.ext.sqlalchemy import get_debug_queries
'''
from . import main
from .forms import PostForm
from ..core import common #wxpayapi, 
#from ..sdk.yuntongxun import SendTemplateSMS as SMS
'''
from .forms import EditProfileForm, EditProfileAdminForm, PostForm,\
    CommentForm
from .. import db
from ..models import Permission, Role, User, Post, Comment
from ..decorators import admin_required, permission_required
'''
from ..models import RolePermissions, Role, User, UserStats, collection
from .. import conf
# from ..models import Post
'''
@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['FLASK_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response


@main.route('/shutdown')
def server_shutdown():
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'
'''
def encrypt():
    context = ['0x01','0x02','0x7d','0x03','0x7e']
    head = ['0x01','0x00','0x00','0x05','0x00','0x00']

    ma = 0x00

    print str(ma)
    for item in context:
        ma+=int(item, 16)

    for item in head:
        ma+=int(item, 16)
    if ma>=136:
        ma = 136
    ma = str(hex(ma))
    print ma
    step1 = ','.join(head)+','.join(context)+ma
    print step1
    step2 = step1.replace('0x7d','0x7d,0x01')
    print step2
    step3 = step2.replace('0x7e','0x7d,0x02')
    print step3
    step4 = '0x7e,'+step3+',0x7e'
    print u'加密后:'+step4
    return step4
def decrypt(s):
    step1 = s[5:len(s)-5]
    
    step2 = step1.replace('0x7d,0x02','0x7e')
    step3 = step2.replace('0x7d,0x01','0x7d')
    ma = step3[len(step3)-4:]
    step4 = step3[:len(step3)-4]
    print u'解密后:'+step4+'_________'+ma


@main.route('/', methods=['GET', 'POST'])
def index():
    uwsgi_reload = request.args.get('reload', 0, type=int)
    if request.method == 'POST':
        form = PostForm()

        page = request.args.get('page', 1, type=int)
        show_followed = False

        print 'post'
    else:

        ret = encrypt()
        decrypt(ret)
        #SMS.sendTemplateSMS('13659488152',['1'],1)
        '''
        print deta.body
        order = wxpayapi.UnifiedOrder_pub()
        order.parameters['out_trade_no'] = '1217752501201407033233368018'
        order.parameters['body'] = 'Ipad mini  16G  白色'
        order.parameters['total_fee'] = '888'
        order.parameters['notify_url'] = '10000'
        order.parameters['trade_type'] = 'APP'

        order.createXml()
        info = order.getPrepayId()
        # orig.get(body='Ross19').update({'$rename': {'body_html': 'body_w'}})
        '''

        '''
        import jpush as jpush
        from ..sdk.jgpush import pushmessage
        #pushmessage(jpush,'口袋专家测试测试11111111',{'type':'viewapp','app_id':157785751945953,'apptype':2},[])
        from flask.ext.login import login_user, logout_user, login_required,current_user
        from ..tests import test_expert, test_user, test_discovery, test_sys
        from flask import g

        from ..sdk.yuntongxun import CreateSubAccount as CSA

        token = rong_api.call_api(
            action="/user/getToken",
            params={
                "userId": str(1),
                "name":'测试',
                "portraitUri":conf.DEFAULT_AVATAR
            }
        )

        print token['token']+'____'+str(token['code'])
        #col1.yuntongxunaccount = ytxaccount

        '''
        #CSA.CreateSubAccount('13659488152')

        #user = User.objects(_id=72).first()
        #login_user(user, True)

        #print user.generate_auth_token(expiration=3600)
        #print '___'+str(user._id)+'___'
        #from ..sdk.getui import igetuipush
        #igetuipush.pushMessageToSingle()
        #print common.getappointmentid(Appointment.createid())
        #test_user.addappointment()
        #test_user.iniuserformat()
        # test_user.adduser()
        # 	test_user.iniroleformat()
        # test_user.addappointment()
        # test_user.iniuserformat()
        # test_expert.initopic(11)
        # test_expert.initopicformat()
        # test_expert.inicommons()
        # test_user.updateuser()
        # test_discovery.initopicformat()
        # print common.getavatar(userid='37')
        # test_sys.addad()
        # test_sys.ini_users_whoosh()
        # print User.getlist_uid(uidlist=[39, 40]).to_json()
        #User.ensure_index('name')
        #User.ensure_index('job')
        #print str((0x01 | 0x02 | 0x04 | 0x08 | 0x80) & 0x01)
        #print str(0x01 | 0x11 | 0x12 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80| 0x100 | 0x200)

        '''
        User.objects().update(unset__stats__oldx=1)
        User.objects().update(unset__stats__baidu=1)
        User.objects().update(unset__stats__zhihu=1)
        User.objects().update(unset__stats__sina=1)
        User.objects().update(unset__stats__twitter=1)
        User.objects().update(unset__stats__facebook=1)
        User.objects().update(unset__stats__github=1)
        User.objects().update(unset__stats__baiduurl=1)
        User.objects().update(unset__stats__zhihuurl=1)
        User.objects().update(unset__stats__sinaurl=1)
        User.objects().update(unset__stats__twitterurl=1)
        User.objects().update(unset__stats__facebookurl=1)
        User.objects().update(unset__stats__githuburl=1)
        '''
        '''
        print str(len(Appointment.getlist()))
        for i in Appointment.getlist():
            print i.id
        print str(0x01 | 0x11 | 0x12 | 0x08 | 0x10)
        print str((0x01 | 0x02 | 0x04 | 0x08) & 0x80) #1、2、4、8、16、32、64、128、256、512  2^(N-1)
        '''
        # deta = Test.objects.exclude('body', 'body_html').get(_id=40)
        if uwsgi_reload == 1:
            import uwsgi  #uwsgi服务支持
            uwsgi.reload()  # 重启uwsgi 服务器
        return render_template('index.html', deta={'body':'token'})

'''

@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('user.html', user=user, posts=posts,
                           pagination=pagination)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)


@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                          post=post,
                          author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published.')
        return redirect(url_for('.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) /
            current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('post.html', posts=[post], form=form,
                           comments=comments, pagination=pagination)


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash('The post has been updated.')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)


@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash('You are already following this user.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash('You are now following %s.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You are not following this user.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followers of",
                           endpoint='.followers', pagination=pagination,
                           follows=follows)


@main.route('/followed-by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)


@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30 * 24 * 60 * 60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30 * 24 * 60 * 60)
    return resp


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
                           pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))
'''
