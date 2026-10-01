"""Serves ATProto XRPC methods by passing through to users' native networks.

Users with accounts bridged into ATProto can log into ATProto clients with
:mod:`atproto_oauth`. Some XRPC methods, eg ``uploadBlob`` and ``createRecord``,
need to write to the user's native account, so we implement them here.

https://github.com/snarfed/bridgy-fed/issues/1785
"""
from arroba.datastore_storage import AtpRemoteBlob, AtpRepo
import arroba.server
from arroba import xrpc_repo
from authlib.integrations.flask_oauth2 import current_token
from flask import request
from granary import as1, bluesky, mastodon, pixelfed
from lexrpc.base import XrpcError
from requests import RequestException
from webutil import util

from activitypub import ActivityPub
import atproto_oauth
import oauth_server


@arroba.server.server.method('com.atproto.repo.uploadBlob', override=True)
def upload_blob(input):
    """Handler for ``com.atproto.repo.uploadBlob``.

    Uploads the blob to the user's native account, then stores an
    :class:`AtpRemoteBlob` for it. Mastodon deletes media that isn't attached to
    a status within a day or so, so :func:`create_record` attaches it to a
    self-DM.

    TODO: support the ``blob:`` permission scope. :mod:`arroba.permissions`
    doesn't support it yet, so we don't check it.
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
        media = source._post(mastodon.API_MEDIA,
                             files={'file': ('file', input, mime_type)})
    except RequestException as e:
        code, body = util.interpret_http_exception(e)
        if code and code.startswith('4'):
            raise XrpcError(f"Couldn't upload media: {body}", name='InvalidRequest')
        raise XrpcError(f"Couldn't upload media: {body or e}",
                        name='UpstreamFailure', status=502)

    # re-fetch the media instead of using input because Mastodon and Pixelfed
    # re-encode uploaded media, eg to strip metadata, and getBlob redirects to
    # their copy. its bytes have to match the blob's CID, otherwise the Bluesky
    # AppView's image proxy won't serve it.
    try:
        blob = AtpRemoteBlob.get_or_create(url=media['url'], repo=AtpRepo(id=did),
                                           get_fn=util.requests_get)
    except RequestException as e:
        raise XrpcError(f"Couldn't fetch uploaded media: {e}",
                        name='UpstreamFailure', status=502)

    blob.remote_id = media['id']
    blob.put()
    return {'blob': blob.as_object()}


@arroba.server.server.method('com.atproto.repo.createRecord', override=True)
def create_record(input):
    """Handler for ``com.atproto.repo.createRecord``.

    Passes through to :func:`arroba.xrpc_repo.create_record`, then also stores a
    self-DM on the user's native account, ie a ``direct`` status with no other
    recipients, with a plain text summary of the record and any media it uses
    that was uploaded with :func:`upload_blob`. Best effort; if the self-DM
    fails, we still return success.
    """
    # xrpc_repo.create_record does authn/authz and raises XrpcError if they fail
    ret = xrpc_repo.create_record(input)

    # TODO: support web/micropub
    if not (token := current_token) or token.user_key.kind() != 'ActivityPub':
        return ret

    did = token.did
    source = oauth_server.granary_source_for(token.user_key)
    if not isinstance(source, (mastodon.Mastodon, pixelfed.Pixelfed)):
        return ret

    record = input['record']
    at_uri = ret['uri']
    try:
        text = as1.snippet(bluesky.to_as1(record, uri=at_uri, repo_did=did))
    except ValueError:
        # probably an unsupported record type
        text = ''

    data = {
        'status': f'{text or input["collection"]}\n\n{at_uri}',
        'visibility': 'direct',
    }

    # collect media_ids from blobs
    def blob_cids(val):
        if isinstance(val, dict):
            if val.get('$type') == 'blob':
                yield bluesky.blob_cid(val)
            else:
                for v in val.values():
                    yield from blob_cids(v)
        elif isinstance(val, list):
            for v in val:
                yield from blob_cids(v)

    if cids := list(blob_cids(record)):
        blobs = AtpRemoteBlob.query(AtpRemoteBlob.cid.IN(cids),
                                    AtpRemoteBlob.repos == AtpRepo(id=did).key)
        data['media_ids'] = util.trim_nulls([blob.remote_id for blob in blobs])

    # post self-DM
    try:
        source._post(mastodon.API_STATUSES, json=data)
    except RequestException as e:
        util.interpret_http_exception(e)

    return ret
