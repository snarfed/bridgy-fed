"""Datastore model classes."""
import logging

import requests

from google.cloud import ndb
from oauth_dropins.webutil.models import StringIdModel
from oauth_dropins.webutil import util
from oauth_dropins.webutil.util import json_dumps, json_loads

logger = logging.getLogger(__name__)
