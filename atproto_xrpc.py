"""Serves ATProto XRPC methods by passing through to users' native networks.

Users with accounts bridged into ATProto can log into ATProto clients with
:mod:`atproto_oauth`. Some XRPC methods, eg ``uploadBlob``, need to write to the
user's native account, so we implement them here.

https://github.com/snarfed/bridgy-fed/issues/1785
"""
from arroba.datastore_storage import AtpRemoteBlob, AtpRepo
import arroba.server
from flask import request
from granary import mastodon, pixelfed
from lexrpc.base import XrpcError
from requests import RequestException
from webutil import util

import atproto_oauth
import oauth_server


@arroba.server.server.method('com.atproto.repo.uploadBlob', override=True)
def upload_blob(input):
    """Handler for ``com.atproto.repo.uploadBlob``.

    Uploads the blob to the user's native account, then stores an
    :class:`AtpRemoteBlob` for it.

    TODO:
    * support the ``blob:`` permission scope. :mod:`arroba.permissions` doesn't
      support it yet, so we don't check it.
    * Mastodon deletes media that isn't attached to a status within a day or so.
      attach it to a self-DM so it persists.
    """
    with atproto_oauth.require_oauth.acquire('atproto') as token:
        did = token.did
        user = token.user_key.get()

    source = oauth_server.granary_source_for(user.key)
    mime_type = request.mimetype or 'application/octet-stream'

    # TODO: generalize
    if not isinstance(source, (mastodon.Mastodon, pixelfed.Pixelfed)):
        raise NotImplementedError(f'{user.LABEL} accounts not supported yet')

    try:
        # TODO: switch to /api/v2/media, which returns 202 and no url if it's
        # still processing the upload
        url = source._post(mastodon.API_MEDIA,
                           files={'file': ('file', input, mime_type)})['url']
    except RequestException as e:
        code, body = util.interpret_http_exception(e)
        if code and code.startswith('4'):
            raise XrpcError(f"Couldn't upload media: {body}", name='InvalidRequest')
        raise XrpcError(f"Couldn't upload media: {body or e}",
                        name='UpstreamFailure', status=502)

    blob = AtpRemoteBlob.get_or_create(url=url, repo=AtpRepo(id=did),
                                       content=input, mime_type=mime_type)
    return {'blob': blob.as_object()}
