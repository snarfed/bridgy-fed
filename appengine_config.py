"""Bridgy App Engine config.
"""
import logging


class StubsFilter(logging.Filter):
    """Suppress these INFO logs:
    Sandbox prevented access to file "/usr/local/Caskroom/google-cloud-sdk"
    If it is a static file, check that `application_readable: true` is set in your app.yaml
    """
    def filter(self, record):
        msg = record.getMessage()
        if (msg.startswith('Sandbox prevented access to file')
                or msg.startswith('If it is a static file, check that')):
            return 0
        return 1


logging.getLogger().addFilter(StubsFilter())
