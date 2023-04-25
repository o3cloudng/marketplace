
from __future__ import absolute_import, unicode_literals

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

app = Celery("core")
# app = Celery('core', CELERY_BROKER_URL = "redis://redis:6379/0", CELERY_RESULT_BACKEND = "redis://redis:6379/0", include=["accounts.tasks"])

app.config_from_object("django.conf:settings", namespace="CELERY")

# CELERY_IMPORTS=("accounts.tasks")

app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))