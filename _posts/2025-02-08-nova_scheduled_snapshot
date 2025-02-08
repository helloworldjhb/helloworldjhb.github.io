---
layout: post

title: "云主机定时快照设计"

subtitle: ""

date: 2025-02-08 18:00:00

author:     "Jobin"
header-img: ""
catalog: true
tags:
    - nova snapshot
---

django集成django-celery实现定时任务

django项目的settings.py中导入celery_config.py如下内容

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import djcelery

from celery import platforms
from kombu import Exchange, Queue

djcelery.setup_loader()

platforms.C_FORCE_ROOT = True

CELERYBEAT_SCHEDULER = 'djcelery.schedulers.DatabaseScheduler'
BROKER_URL = base.CELERY_BROKER_URL
# TODO: OSError: Socket closed in celery worker with eventlet
BROKER_HEARTBEAT = 0
CELERY_RESULT_BACKEND = base.CELERY_RESULT_BACKEND

CELERY_IMPORTS = (
    'tri_lib.nova.task',
)
CELERY_IGNORE_RESULT = True
CELERYD_CONCURRENCY = 4
CELERY_ACKS_LATE = False
CELERYD_MAX_TASKS_PER_CHILD = 100
CELERYD_TASK_TIME_LIMIT = 12 * 30

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Asia/Shanghai'
CELERY_ENABLE_UTC = False

CELERY_QUEUES = (
    Queue('scheduled_instance_snapshot', Exchange('scheduled_instance_snapshot'),
          routing_key='scheduled_instance_snapshot'),
)
CELERY_ROUTES = {
    'create_server_snapshot': {'queue': 'scheduled_instance_snapshot', 'routing_key': 'scheduled_instance_snapshot'}
}
```

加载的定时任务tri_lib.nova.task.py

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
from celery import Task

from tri_lib.logging_custom import getLogger
from tri_lib.nova import client as nova_client
from tri_lib.tools.utils import get_nova_session
from tri_lib.tools.thread_manager import ThreadManager
from tri_lib.nova.periodic_delete import add_delete_task
from tri_lib.databases.server_strategy_assign import AssignManager
from tri_lib import exc

logger = getLogger()


class ProcessTask(Task):
    ignore_result = True
    name = 'create_server_snapshot'

    def run(self, *args, **kwargs):
        self.create_server_snapshot(*args, **kwargs)

    @exc.capture_exception_with_i18n()
    def create_server_snapshot(self, *args, **kwargs):
        project_id = kwargs.get('project_id')
        strategy_id = kwargs.get('strategy_id')
        purge_time = kwargs.get('purge_time')

        session = get_nova_session()
        nova_cli = nova_client.get_client_by_session(session=session)

        assign_manager = AssignManager()
        assignments = assign_manager.list(search_opts={'strategy_id': strategy_id})
        server_id_list = [assignment['server_id'] for assignment in assignments]

        task_list = []
        for server_id in server_id_list:
            time_local = time.localtime(int(time.time()))
            suffix = time.strftime("%Y-%m-%d_%H-%M", time_local)

            servers = nova_cli.servers.list(search_opts={'all_tenants': True, 'uuid': server_id})
            if servers:
                server = servers[0].to_dict()
                server_name = server['name']
                image_name = server_name + '_' + suffix
                task_list.append({'target': self._create_server_snapshot, 'args': (nova_cli,
                                                                                   project_id,
                                                                                   server_id,
                                                                                   image_name,
                                                                                   purge_time,
                                                                                   strategy_id), 'key': image_name})

        ThreadManager().batch(task_list)

    def _create_server_snapshot(self, nova_cli, project_id, server_id, image_name, purge_time, strategy_id):
        try:
            image_id = nova_cli.servers.create_image(server_id, image_name, metadata={"owner": project_id,
                                                                                      "instance_uuid": server_id,
                                                                                      "image_type": "vmsnap",
                                                                                      "periodic": "yes",
                                                                                      "strategy_id": strategy_id})
        except Exception as ex:
            logger.warning(
                u'failed to create server snapshot: {}, the reason is {}'.format(image_name, ex))
        else:
            logger.info(u'success create server snapshot: {}'.format(image_name))
            if purge_time > 0:
                server_snapshot_id = image_id
                logger.info(u"add the id {} of server snapshot {} to delay queue".format(server_snapshot_id,
                                                                                         image_name))
                add_delete_task(server_snapshot_id, purge_time)
```

add_delete_task将云主机定时快照注入到延迟队列，时序图如下所示

![云主机定时快照生成](云主机定时快照生成.jpg)

启动延迟队列定时器，探测延迟队列中的云主机定时快照是否过期

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import threading

from tri_lib.logging_custom import getLogger
from tri_lib.tools.delayqueue import delay_queue
from tri_lib.tools.utils import get_admin_session


logger = getLogger()

delete_image_threads_names = []
TOPIC = 'server_snapshot'


def execute():
    logger.info('Initialize scheduled instance snapshot delay queue')

    from tri_lib.glance.images import ImageManager
    # initialize delay queue
    delay_queue.init()

    while True:
        # get job by pop
        # multiple topics separated by commas
        topics = TOPIC.split(',')
        job = delay_queue.pop(topics)

        if job:
            image_id = job['id']
            session = get_admin_session()
            image_manager = ImageManager(session=session)
            logger.info("start to delete server snapshot id: {}".format(image_id))
            th = threading.Thread(target=image_manager.delete_image, args=(image_id,))
            th.start()

            logger.info('delete job id: {}'.format(image_id))
            delay_queue.remove(image_id)
```

时序图如下所示

![云主机定时快照删除](云主机定时快照删除.jpg)

最后通过websocket向页面推送redis缓存的云主机定时快照的剩余保留时间
