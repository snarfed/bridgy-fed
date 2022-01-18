![](https://raw.github.com/snarfed/bridgy/master/static/bridgy_logo_thumb.jpg) [Bridgy Fed](https://fed.brid.gy/) [![Circle CI](https://circleci.com/gh/snarfed/bridgy-fed.svg?style=svg)](https://circleci.com/gh/snarfed/bridgy-fed) [![Coverage Status](https://coveralls.io/repos/github/snarfed/bridgy-fed/badge.svg?branch=master)](https://coveralls.io/github/snarfed/bridgy-fed?branch=main)
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
python3 -m venv local
source local/bin/activate
pip install -r requirements.txt
```

Now, run the tests to check that everything is set up ok:

```shell
gcloud beta emulators datastore start --no-store-on-disk --consistency=1.0 --host-port=localhost:8089 < /dev/null >& /dev/null &
python3 -m unittest discover
```

Finally, run this in the repo root directory to start the web app locally:

```shell
GAE_ENV=localdev FLASK_ENV=development flask run -p 8080
```


If you send a pull request, please include (or update) a test for the new functionality!

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

You may need to change [granary](https://github.com/snarfed/granary), [oauth-dropins](https://github.com/snarfed/oauth-dropins), [mf2util](https://github.com/kylewm/mf2util), or other dependencies as well as as Bridgy Fed. To do that, clone their repo locally, then install them in "source" mode with e.g.:

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
* [Pleroma](https://pleroma.social/)
  * [snarfed@cawfee.club](https://cawfee.club/snarfed)

### OStatus / Salmon

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

Stats
---

I occasionally generate stats and graphs of usage and growth via BigQuery, [like I do with Bridgy](https://bridgy.readthedocs.io/#stats). Here's how.

1. [Export the full datastore to Google Cloud Storage.](https://cloud.google.com/datastore/docs/export-import-entities) Include all entities except `MagicKey`. Check to see if any new kinds have been added since the last time this command was run.

    ```
    gcloud datastore export --async gs://bridgy-federated.appspot.com/stats/ --kinds Follower,Response
    ```

    Note that `--kinds` is required. [From the export docs](https://cloud.google.com/datastore/docs/export-import-entities#limitations):
    > _Data exported without specifying an entity filter cannot be loaded into BigQuery._
1. Wait for it to be done with `gcloud datastore operations list | grep done`.
1. [Import it into BigQuery](https://cloud.google.com/bigquery/docs/loading-data-cloud-datastore#loading_cloud_datastore_export_service_data):

    ```
    for kind in Follower Response; do
      bq load --replace --nosync --source_format=DATASTORE_BACKUP datastore.$kind gs://bridgy-federated.appspot.com/stats/all_namespaces/kind_$kind/all_namespaces_kind_$kind.export_metadata
    done
    ```
1. Check the jobs with `bq ls -j`, then wait for them with `bq wait`.
1. [Run the full stats BigQuery query.](https://console.cloud.google.com/bigquery?sq=664405099227:58879d2908824a21b737eee98fff2de8) Download the results as CSV.
1. [Open the stats spreadsheet.](https://docs.google.com/spreadsheets/d/1OtOZ2Rb4EqAGEp9rHziWkyJD4BaRFb_971KjOqMKePA/edit) Import the CSV, replacing the _data_ sheet.
1. Check out the graphs! Save full size images with OS or browser screenshots, thumbnails with the _Download Chart_ button.
