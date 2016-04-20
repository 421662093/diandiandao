#!/usr/bin/env python
#-*- coding: utf-8 -*-
import os
import time
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SECRET_SALT = 'activate-salt'
    SSL_DISABLE = False
    '''
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_RECORD_QUERIES = True
    '''
    #MAIL_SERVER = 'smtp.googlemail.com'
    #MAIL_PORT = 587
    #MAIL_USE_TLS = True
    #MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    #MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    #FLASK_MAIL_SUBJECT_PREFIX = '[Flask]'
    #FLASK_MAIL_SENDER = 'Flask Applicationdmin <flask@example.com>'
    FLASK_ADMIN = os.environ.get('FLASK_ADMIN')


    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    WHOOSH_BASE = 'path/to/whoosh/base'
    DEBUG = True
    # mongodb://user1:password1@localhost/test
    MONGODB_SETTINGS = {
        'db': 'fullteck',#clr
        'host': 'mongodb://localhost:27017/'
    }

    DEFAULT_AVATAR='http://182.254.221.13:8080/static/default.png' #默认头像

    #腾讯云API
    QCLOUDAPI_SECRET_ID = 'AKIDd2vXFqBjcWRfWlCe7TsYNKyn76FALI85'
    QCLOUDAPI_SECRET_KEY = 'ElpeYhStMAPR63KlKan1t9ShbzAzjoYG'
    QCLOUDAPI_YUNSOU_APPID = '31040002' #云搜appid

    #腾讯云缓存Memcached
    QCLOUD_MEMCACHED_IP = '10.66.108.120:9101'

    #万象优图
    QCLOUD_APPID = '10001870' #项目ID
    QCLOUD_SECRET_ID = 'AKIDBFlEhtzhepEthyhzGvZ5jI3AGbL6oumH'
    QCLOUD_SECRET_KEY = '8bw7cA3KGdTdk1FerPkL7n94Kdx0LrE0'
    QCLOUD_BUCKET = 'kdzj2015' #空间名称

    PINGPP_APP_ID = 'app_9qXXjTvjHW98Tmv9'
    PINGPP_API_KEY = 'sk_live_FSqiwUW3uBeY5u47xMskEFtW'

    JPush_API_KEY = '2d85bc2c4cc44f976c26286d'
    JPush_MASTER_SECRET = '9e245d142adba0289b329b73'

    #容联云通讯
    YUNTONGXUN_SID = 'aaf98f894ecd7d6a014ed28bb38c0783' #主账号 ACCOUNT SID
    YUNTONGXUN_TOKEN = '02a449a36fa347aba7ed5854b7f80c21' #主账号 AUTH TOKEN
    YUNTONGXUN_APPID = 'aaf98f894ecd7d6a014ed2a653c10813' #APPID

    RONGCLOUD_APP_KEY = 'pvxdm17jxqi5r'
    RONGCLOUD_APP_SECRET = 'RoKfTA4d4DzlLM'
    #RECHARGE_SCALE = 1 #充值比例 1:5  1人民币兑换5个专家币

    SHARE_CALL_TIME = 30 #分享获通话时间 默认每次分享可获得30分钟，一种途径一天可分享1次

    HIDE_PAY = 1 #隐藏支付功能

    #上传配置
    UPLOAD_FOLDER = 'uploads' #上传目录
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 #上传大小限制
    ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif']) #限制格式

    DOMAIN = {1: '新金融', 2: '教育', 3: '企业服务', 4: '电商', 5: '游戏', 6: '互联网', 7: '硬件',
              8: '文化创意', 9: '快消', 10: '医疗健康', 11: '新农业', 12: '本地生活', 13: '房地产', 14: '汽车'}

    INDUSTRY = {1: '媒体', 2: '自媒体', 3: '投资人', 4: '创业者', 5: '技术', 6: '设计', 7: '产品经理',
                8: '营销', 9: '策划', 10: '市场', 11: '公关', 12: '运营', 13: '人力资源', 14: '管理'}

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        import logging  # 日志系统

        logging.basicConfig(level=logging.DEBUG,
                            format='%(filename)s[line:%(lineno)d] %(levelname)s [%(message)s] %(asctime)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            filename='log/flask.log',
                            filemode='w')

        DEBUG = logging.StreamHandler()
        DEBUG.setLevel(logging.DEBUG)
        ERROR = logging.StreamHandler()
        ERROR.setLevel(logging.ERROR)  #

        #logging.debug('This is debug message')
        #logging.info('This is info message')
        #logging.warning('app staart')
        logging.debug('flask start')
        ###########
        # formatter = logging.Formatter(
        #    '%(name)-12s: %(levelname)-8s %(message)s')
        # console.setFormatter(formatter)
        ###########
        app.logger.addHandler(DEBUG)
        app.logger.addHandler(ERROR)



class TestingConfig(Config):
    TESTING = True
    DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # email errors to the administrators
        import logging
        from logging.handlers import SMTPHandler
        credentials = None
        secure = None
        if getattr(cls, 'MAIL_USERNAME', None) is not None:
            credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
            if getattr(cls, 'MAIL_USE_TLS', None):
                secure = ()
        mail_handler = SMTPHandler(
            mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
            fromaddr=cls.FLASKY_MAIL_SENDER,
            toaddrs=[cls.FLASKY_ADMIN],
            subject=cls.FLASKY_MAIL_SUBJECT_PREFIX + ' Application Error',
            credentials=credentials,
            secure=secure)
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)


class HerokuConfig(ProductionConfig):
    SSL_DISABLE = bool(os.environ.get('SSL_DISABLE'))

    @classmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)

        # handle proxy server headers
        from werkzeug.contrib.fixers import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app)

        # log to stderr
        import logging
        from logging import StreamHandler
        file_handler = StreamHandler()
        file_handler.setLevel(logging.WARNING)
        app.logger.addHandler(file_handler)


class UnixConfig(ProductionConfig):

    @classmethod
    def init_app(cls, app):
        ProductionConfig.init_app(app)

        # log to syslog
        import logging
        from logging.handlers import SysLogHandler
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.WARNING)
        app.logger.addHandler(syslog_handler)


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'heroku': HerokuConfig,
    'unix': UnixConfig,

    'default': DevelopmentConfig
}
