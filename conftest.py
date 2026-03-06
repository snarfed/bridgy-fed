"""Config for pytest and pytest-xdist (parallel test runner).

I run with:

cd ~/src/bridgy-fed/ && ve && fullpower pytest -n 6 --dist=worksteal --disable-warnings tests
"""
import os

from oauth_dropins.webutil import appengine_info

appengine_info.TESTING = True
appengine_info.LOCAL_SERVER = False

# Each worker needs its own datastore emulator
worker = os.environ.get('PYTEST_XDIST_WORKER', 'gw0')
port = 8089 + (int(worker[2:]) if worker.startswith('gw') else 0)
os.environ['DATASTORE_EMULATOR_HOST'] = f'localhost:{port}'
