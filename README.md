![](https://raw.github.com/snarfed/bridgy-federated/master/static/bridgy_logo_thumb.jpg) [Bridgy Fed](https://fed.brid.gy/) [![Circle CI](https://circleci.com/gh/snarfed/bridgy-federated.svg?style=svg)](https://circleci.com/gh/snarfed/bridgy-federated) [![Coverage Status](https://coveralls.io/repos/github/snarfed/bridgy-federated/badge.svg?branch=master)](https://coveralls.io/github/snarfed/bridgy-federated?branch=master)
===

Got an [IndieWeb](https://indieweb.org/) site? Want to interact with people on [Mastodon](https://joinmastodon.org/), [GNU Social](https://gnu.io/social/), and more? Bridgy Fed is for you.

https://fed.brid.gy/

Bridgy Fed connects the [IndieWeb](https://indieweb.org/) with federated social networks using [ActivityPub](https://activitypub.rocks/) and [OStatus](https://en.wikipedia.org/wiki/OStatus):

  * [Diaspora](https://diasporafoundation.org/)
  * [Friendica](http://friendi.ca/)
  * [GNU Social](https://gnu.io/social/) (née StatusNet)
  * [Hubzilla](https://project.hubzilla.org/)
  * [MediaGoblin](https://mediagoblin.org/)
  * [Mastodon](https://joinmastodon.org/)
  * [postActiv](https://postactiv.com/)
  * [pump.io](http://pump.io/)
  * ...and more!

Original design docs:

* https://snarfed.org/indieweb-activitypub-bridge
* https://snarfed.org/indieweb-ostatus-bridge

License: This project is placed in the public domain.


Development
---
You'll need the [App Engine Python SDK](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python) version 1.9.15 or later (for [`vendor`](https://cloud.google.com/appengine/docs/python/tools/libraries27#vendoring) support) or the [Google Cloud SDK](https://cloud.google.com/sdk/gcloud/) (aka `gcloud`) with the `gcloud-appengine-python` and `gcloud-appengine-python-extras` [components](https://cloud.google.com/sdk/docs/components#additional_components). Add it to your `$PYTHONPATH`, e.g. `export PYTHONPATH=$PYTHONPATH:/usr/local/google_appengine`, and then run:

```sh
virtualenv local
source local/bin/activate
pip install -r requirements.txt
python -m unittest discover
```

The last command runs the unit tests. If you send a pull request, please include (or update) a test for the new functionality!

If you hit an error during setup, check out the [oauth-dropins Troubleshooting/FAQ section](https://github.com/snarfed/oauth-dropins#troubleshootingfaq). For searchability, here are a handful of error messages that [have solutions there](https://github.com/snarfed/oauth-dropins#troubleshootingfaq):

```
bash: ./bin/easy_install: ...bad interpreter: No such file or directory

ImportError: cannot import name certs

ImportError: No module named dev_appserver

ImportError: cannot import name tweepy

File ".../site-packages/tweepy/auth.py", line 68, in _get_request_token
  raise TweepError(e)
TweepError: must be _socket.socket, not socket

error: option --home not recognized
```

You may need to change [granary](https://github.com/snarfed/granary), [oauth-dropins](https://github.com/snarfed/oauth-dropins), [webmention-tools](https://github.com/snarfed/webmention-tools), [mf2util](https://github.com/kylewm/mf2util), or other dependencies as well as as Bridgy Fed. To do that, clone their repo locally, then install them in "source" mode with e.g.:

```sh
pip uninstall -y granary
pip install -e <path to granary>
ln -s <path to granary>/granary \
  local/lib/python2.7/site-packages/granary
```

The symlinks are necessary because App Engine's `vendor` module evidently
doesn't follow `.egg-link` or `.pth` files. :/

To deploy to App Engine, run:

```sh
gcloud -q app deploy --project bridgy-federated *.yaml
```
