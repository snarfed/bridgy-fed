"""Superfeedr callback handlers.

Not really sure what this will be yet. Background:
https://github.com/snarfed/bridgy-fed/issues/18#issuecomment-430731476
https://documentation.superfeedr.com/publishers.html
"""
import logging

from flask import request

from app import app


@app.route(r'/superfeedr/', methods=['GET', 'POST'])
@app.route(r'/superfeedr/<path:_>', methods=['GET', 'POST'])
def superfeedr(_=None):
    """Superfeedr subscription callback handler.

    https://documentation.superfeedr.com/publishers.html#subscription-callback
    """
    logging.info(f'Got:\n{request.get_data(as_text=True)}')
    return '', 204
