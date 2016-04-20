# coding:utf-8
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
#from .. import scheduler
'''
scheduler = BackgroundScheduler()
#from .core import tasks #定时任务系统
try:
    scheduler.start()
except (KeyboardInterrupt, SystemExit):
    scheduler.shutdown()

@scheduler.scheduled_job('cron', id='my_job_id', second='*/3', hour='*')
def tick():
    print('Tick! The time is: %s' % datetime.now())
'''
