![](https://raw.github.com/snarfed/bridgy/master/static/bridgy_logo_thumb.jpg) [Bridgy Fed](https://fed.brid.gy/) [![Circle CI](https://circleci.com/gh/snarfed/bridgy-fed.svg?style=svg)](https://circleci.com/gh/snarfed/bridgy-fed) [![Coverage Status](https://coveralls.io/repos/github/snarfed/bridgy-fed/badge.svg?branch=master)](https://coveralls.io/github/snarfed/bridgy-fed?branch=master)
===

Got an [IndieWeb](https://indieweb.org/) site? Want to interact with federated social networks like [Mastodon](https://joinmastodon.org/), [Hubzilla](https://project.hubzilla.org/), and more? Bridgy Fed is for you.

https://fed.brid.gy/

Bridgy Fed connects the [IndieWeb](https://indieweb.org/) with federated social networks using [ActivityPub](https://activitypub.rocks/) and [OStatus](https://en.wikipedia.org/wiki/OStatus). Original design docs:

* https://snarfed.org/indieweb-activitypub-bridge
* https://snarfed.org/indieweb-ostatus-bridge

License: This project is placed in the public domain.


Development
---
You'll need Python 3. Install the [Google Cloud SDK](https://cloud.google.com/sdk/gcloud/) (aka `gcloud`) with the `gcloud-appengine-python` and `gcloud-appengine-python-extras` [components](https://cloud.google.com/sdk/docs/components#additional_components). Then, run:

```sh
python3 -m venv local3
source local3/bin/activate
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
```

To deploy to the production instance on App Engine - if @snarfed has added you as an owner - run:

```sh
gcloud -q beta app deploy --no-cache --project bridgy-federated *.yaml
```


Compatibility
---
Here are in progress notes on how I'm testing interoperability with various federated social networks.

### ActivityPub

* [Mastodon](https://joinmastodon.org/) ([issue](https://github.com/tootsuite/mastodon/issues/1557)) works! [They shipped support in 1.6.](https://github.com/tootsuite/mastodon/releases/tag/v1.6.0rc1)
  * [snarfed@mastodon.technology](https://mastodon.technology/@snarfed), [example post](https://mastodon.technology/@snarfed/2604611)
* [Hubzilla](https://project.hubzilla.org/) [is getting close](https://hub.somaton.com/channel/mario/&f=&mid=6db16e0e253c3c376cb921e7b31f94c24522933d7e54c6cf9febaa05359ab2fe@hub.somaton.com)!
  * Old since lastauth.com is down now: ~~[snarfed@lastauth.com](https://lastauth.com/channel/snarfed), [example post](https://lastauth.com/channel/snarfed/?mid=7cfa12e54cf97aaed3b0bb185651ae37a1e24027fbf3e845fab261e108392707@lastauth.com)~~
* [distbin](http://distbin.com/)
  * No explicit accounts, can post anything as anyone
* [pump.io](http://pump.io/)
  * [snarfed@datamost.com](https://datamost.com/snarfed)
  * Tried posting a bunch of ways, couldn't get any to work :/
* [Kroeg](https://github.com/puckipedia/Kroeg)
  * Not open to other users yet. Seems to be running at [puckipedia.com/social](https://puckipedia.com/social).

### Salmon

* [Friendica](http://friendi.ca/)
  * [snarfed@libranet.de](https://libranet.de/profile/snarfed)
  * Example post: [HTML](https://libranet.de/display/snarfed/3453879) ([alternate link](https://libranet.de/display/0b6b25a814599c43b430890795887058)), [Atom](https://libranet.de/display/snarfed/3453879.atom)
  * Atom has Salmon link rel, `author.dfrn:handle` is user URI (dfrn is http://purl.org/macgirvin/dfrn/1.0))
* [GNU Social](https://gnu.io/social/) (née StatusNet)
  * [snarfed@quitter.se](https://quitter.se/snarfed)
  * Example post: [HTML](https://quitter.se/notice/17459493), [Atom](https://quitter.se/api/statuses/show/17459493.atom)
  * Atom has _no_ Salmon link rels! `author.name` is username (snarfed)
* [Hubzilla](https://project.hubzilla.org/)
  * [snarfed@lastauth.com](https://lastauth.com/channel/snarfed)
  * Example post: [HTML](https://lastauth.com/channel/snarfed/?mid=7cfa12e54cf97aaed3b0bb185651ae37a1e24027fbf3e845fab261e108392707@lastauth.com)
  * Only has Atom `link rel="alternate"` for [full feed](https://lastauth.com/feed/snarfed?f=&top=1), not individual post :/
  * Atom feed has Salmon link rels inside top level `feed`, not in individual `entry`s
  * Atom entries have  `author.name` as username (snarfed)
* [Mastodon](https://joinmastodon.org/)
  * [snarfed@mastodon.technology](https://mastodon.technology/@snarfed)
  * Example post: [HTML](https://mastodon.technology/@snarfed/2604611), [Atom](https://mastodon.technology/users/snarfed/updates/73978.atom)
  * Profile HTML/Atom have Salmon link rel. Individual post HTML/Atom don't. `author.email` is snarfed@mastodon.technology
