<img src="https://raw.github.com/snarfed/bridgy-fed/main/static/bridgy_logo.jpg" width="120" /> [Bridgy Fed](https://fed.brid.gy/) [![Circle CI](https://dl.circleci.com/status-badge/img/gh/snarfed/bridgy-fed/tree/main.svg?style=svg)](https://circleci.com/gh/snarfed/bridgy-fed) [![Coverage Status](https://coveralls.io/repos/github/snarfed/bridgy-fed/badge.svg)](https://coveralls.io/github/snarfed/bridgy-fed)
===

Bridgy Fed connects different decentralized social network protocols. It currently supports the [fediverse](https://en.wikipedia.org/wiki/Fediverse) (eg [Mastodon](https://joinmastodon.org)) via [ActivityPub](https://activitypub.rocks/), [Bluesky](https://bsky.social/) via the [AT Protocol](https://atproto.com/), and the [IndieWeb](https://indieweb.org/) via [webmentions](https://webmention.net/) and [microformats2](https://microformats.org/wiki/microformats2). [Farcaster](https://github.com/snarfed/bridgy-fed/issues/447) and [Nostr](https://github.com/snarfed/bridgy-fed/issues/446) are under consideration. Bridgy Fed translates profiles, likes, reposts, mentions, follows, and more from any supported network to any other. [See the user docs](https://fed.brid.gy/docs) and [developer docs](https://bridgy-fed.readthedocs.io/) for more details.

https://fed.brid.gy/

License: This project is placed in the public domain. You may also use it under the [CC0 License](https://creativecommons.org/publicdomain/zero/1.0/).


Development
---
Development reference docs are at [bridgy-fed.readthedocs.io](https://bridgy-fed.readthedocs.io/). Pull requests are welcome! Feel free to [ping me in #indieweb-dev](https://indieweb.org/discuss) with any questions.

First, fork and clone this repo. Then, install the [Google Cloud SDK](https://cloud.google.com/sdk/) and run `gcloud components install cloud-firestore-emulator` to install the [Firestore emulator](https://cloud.google.com/firestore/docs/emulator). Once you have them, set up your environment by running these commands in the repo root directory:


```sh
gcloud config set project bridgy-federated
python3 -m venv local
source local/bin/activate
pip install -r requirements.txt
# needed to serve static files locally
ln -sf local/lib/python3*/site-packages/oauth_dropins/static oauth_dropins_static
```

You can also use `uv` instead of `pip`, but if you do, pass it `--no-sources`.

Now, run the tests to check that everything is set up ok:

```shell
gcloud emulators firestore start --host-port=:8089 --database-mode=datastore-mode < /dev/null >& /dev/null &
python3 -m unittest discover
```

Finally, run this in the repo root directory to start the web app locally:

```shell
env FLASK_ENV=development APPVIEW_HOST=api.bsky.app PLC_HOST=plc.directory BGS_HOST=bsky.network PDS_HOST=atproto.brid.gy flask --debug run -p 8080
```

If you send a pull request, please include (or update) a test for the new functionality!

You may need to change [granary](https://github.com/snarfed/granary), [oauth-dropins](https://github.com/snarfed/oauth-dropins), [mf2util](https://github.com/kylewm/mf2util), or other dependencies as well as as Bridgy Fed. To do that, clone their repo locally, then install them in "source" mode with e.g.:

```sh
pip uninstall -y granary
pip install -e <path to granary>
```

To deploy to the production instance on App Engine - if @snarfed has added you as an owner - run:

```sh
gcloud -q beta app deploy --no-cache --project bridgy-federated *.yaml
```


How to add a new protocol
---

1. Determine [how you'll map the new protocol to other existing Bridgy Fed protocols](https://fed.brid.gy/docs#translate), specifically identity, protocol inference, events, and operations. [Add those to the existing tables in the docs](https://github.com/snarfed/bridgy-fed/blob/main/templates/docs.html) in a PR. This is an important step before you start writing code.
1. Add the new protocol to `DEBUG_PROTOCOLS` in [`models.py`](https://github.com/snarfed/bridgy-fed/blob/main/models.py).
1. Implement the id and handle conversions in [`ids.py`](https://github.com/snarfed/bridgy-fed/blob/main/ids.py).
1. If the new protocol uses a new data format - which is likely - add that format to [granary](https://github.com/snarfed/granary) in a new file with functions that convert to/from [ActivityStreams 1](https://activitystrea.ms/specs/json/1.0/) and tests. See [`nostr.py`](https://github.com/snarfed/granary/blob/main/granary/nostr.py) and [`test_nostr.py`](https://github.com/snarfed/granary/blob/main/granary/tests/test_nostr.py) for examples.
1. Implement the protocol in a new `.py` file as a subclass of both [`Protocol`](https://github.com/snarfed/bridgy-fed/blob/main/protocol.py) and [`User`](https://github.com/snarfed/bridgy-fed/blob/main/models.py). Implement `send`, `fetch`, `serve`, `target_for`, `create_for`, and other necessary methods from `Protocol`, and `handle`, `handle_for_id`, `web_url`, and other necessary methods from `User` .
1. TODO: add a new usage section to the docs for the new protocol.
1. TODO: does the new protocol need any new UI or signup functionality? Unusual, but not impossible. Add that if necessary.
1. Protocol logos may be emoji and/or image files. If this one has a file, add it `static/`. Then add the emoji and/or file `<img>` tag to the `Protocol` subclass's `LOGO_EMOJI` and/or `LOGO_HTML` constants.


How to post as the protocol bot accounts: @ap.brid.gy, @bsky.brid.gy, etc
---
The protocol bot accounts - [@ap.brid.gy](https://bsky.app/profile/ap.brid.gy), [@bsky.brid.gy](https://mastodon.social/@bsky.brid.gy@bsky.brid.gy), and so on - don't have user-facing UIs to log into and post as, but it's still possible to post as them! And repost etc. Here's how.

They're currently set up as [bridged _web_ accounts](https://fed.brid.gy/docs#web-get-started). To post to them, first create a blog post _without title_ on [snarfed.org](https://snarfed.org/), _check that it's under 300 chars for Bluesky_, then send a [webmention](https://webmention.net/) to Bridgy Fed to make it bridge the post. The source should be of the form eg `https://[subdomain].brid.gy/internal/[URL]`, where URL is the snarfed.org post's URL, _without_ `https://`, eg `https://ap.brid.gy/internal/snarfed.org/2025-06-09_55084`.

```
cd ~/src/bridgy-fed && curl -v -H "Authorization: `cat flask_secret_key`" \
  -d source=https://ap.brid.gy/internal/snarfed.org/... \
  -d force=true \
  https://fed.brid.gy/webmention

cd ~/src/bridgy-fed && curl -v -H "Authorization: `cat flask_secret_key`" \
  -d source=https://bsky.brid.gy/internal/snarfed.org/... \
  -d force=true \
  https://fed.brid.gy/webmention
```

(Ideally we'd like to be able to do this from [blog.anew.social](https://blog.anew.social/) too! [They don't support microformats in the default theme](https://indieweb.org/Ghost#Rejected_microformats2_markup_in_default_theme), though, so we'd need to switch to a microformats-enabled theme first. 😕)


Load balancer
---
One part of our production architecture on GCP is a [Global Application Load Balancer](https://docs.cloud.google.com/load-balancing/docs/load-balancing-overview#application-lb). This lets us do layer 7 (ie HTTP) routing, by URL path, across both App Engine and Cloud Run.

The URL routing is in [`url-map.yaml`](https://github.com/snarfed/bridgy-fed/blob/main/url-map.yaml). Here's how set up the load balancer:

```sh
# Create ALB on https://console.cloud.google.com/net-services/loadbalancing/list/loadBalancers?project=bridgy-federated


# Create serverless NEGs
# https://console.cloud.google.com/compute/networkendpointgroups/list?project=bridgy-federated

gcloud compute network-endpoint-groups create hub --region=us-central1 --network-endpoint-type=SERVERLESS --app-engine-service=hub

gcloud compute network-endpoint-groups create frontend --region=us-central1 --network-endpoint-type=SERVERLESS --cloud-run-service=frontend


# Create backend services, attach NEGs
#
# note that serverless NEGs don't support most backend services' options/flags,
# they need to be left to their defaults.
#
# specifically, they'll say their IP address selection policy is IPv4 only
# (the default), but it doesn't matter, serverless NEGs don't actually use that.

gcloud compute backend-services create hub --global --load-balancing-scheme=EXTERNAL_MANAGED
gcloud compute backend-services add-backend hub --global --network-endpoint-group=hub --network-endpoint-group-region=us-central1

gcloud compute backend-services create frontend --global --load-balancing-scheme=EXTERNAL_MANAGED
gcloud compute backend-services add-backend frontend --global --network-endpoint-group=frontend --network-endpoint-group-region=us-central1


# Validate and import url-map.yaml

gcloud compute url-maps validate --source=url-map.yaml

gcloud compute url-maps import bridgy-fed --source=url-map.yaml --global


# Reserve IPs, create SSL cert
# https://console.cloud.google.com/networking/addresses/list?project=bridgy-federated

gcloud compute addresses create load-balancer --ip-version=IPV4 --global
gcloud compute addresses create lb-ipv6-address --ip-version=IPV6 --global

# https://console.cloud.google.com/networking/addresses/list?project=bridgy-federated
136.68.247.97
2600:1901:0:584a::

# now add DNS for foo.brid.gy with a single A record pointing to 136.68.247.97

gcloud compute ssl-certificates create managed-ssl-cert --domains=foo.brid.gy,... --global

gcloud compute ssl-certificates describe managed-ssl-cert

# https://console.cloud.google.com/security/ccm/list/lbCertificates?project=bridgy-federated

# for a real prod domain like atproto.brid.gy, I made a cert with DNS Authorization instead. doable in the web console and with gcloud.
# https://docs.cloud.google.com/certificate-manager/docs/dns-authorizations


# Create target HTTP[S] proxies, forwarding rules

gcloud compute target-https-proxies create bridgy-fed --ssl-certificates=managed-ssl-cert --url-map=bridgy-fed --global

gcloud compute target-http-proxies create bridgy-fed-http --url-map=bridgy-fed --global

gcloud compute forwarding-rules create bridgy-fed --load-balancing-scheme=EXTERNAL_MANAGED --address=load-balancer --target-https-proxy=bridgy-fed --ports=443 --global

gcloud compute forwarding-rules create bridgy-fed-ipv6 --load-balancing-scheme=EXTERNAL_MANAGED --address=lb-ipv6-address --target-https-proxy=bridgy-fed --ports=443 --global

gcloud compute forwarding-rules create bridgy-fed-http --load-balancing-scheme=EXTERNAL_MANAGED --address=load-balancer --target-http-proxy=bridgy-fed-http --ports=80 --global

gcloud compute forwarding-rules create bridgy-fed-http-ipv6 --load-balancing-scheme=EXTERNAL_MANAGED --address=lb-ipv6-address --target-http-proxy=bridgy-fed-http --ports=80 --global


# view!

https://console.cloud.google.com/net-services/loadbalancing/details/httpAdvanced/bridgy-fed?project=bridgy-federated
```


GCP Artifact Registry cleanup policies
---
`[artifact-registry-cleanup-policy.json](https://github.com/snarfed/bridgy-fed/blob/main/artifact-registry-cleanup-policy.json)` is an [Artifact Registry cleanup policy](https://docs.cloud.google.com/artifact-registry/docs/repositories/cleanup-policy) that automatically deletes old Docker images built by Cloud Build in our repos. [Background.](https://github.com/snarfed/bridgy-fed/issues/2473)

Apply with:

```sh
gcloud artifacts repositories set-cleanup-policies gae-flexible \
    --location us-central1 \
    --policy=artifact-registry-cleanup-policy.json

gcloud artifacts repositories set-cleanup-policies gae-standard \
    --location us-central1 \
    --policy=artifact-registry-cleanup-policy.json

gcloud artifacts repositories set-cleanup-policies cloud-run-source-deploy \
    --location us-central1 \
    --policy=artifact-registry-cleanup-policy.json
```


Stats
---

I occasionally generate stats and graphs of usage and growth via BigQuery, [like I do with Bridgy](https://bridgy.readthedocs.io/#stats). Here's how.

1. [Export the full datastore to Google Cloud Storage.](https://cloud.google.com/datastore/docs/export-import-entities) Include all entities except `MagicKey`. Check to see if any new kinds have been added since the last time this command was run.

    ```
    gcloud datastore export --async gs://bridgy-federated.appspot.com/stats/ --kinds Follower,Object
    ```

    Note that `--kinds` is required. [From the export docs](https://cloud.google.com/datastore/docs/export-import-entities#limitations):
    > _Data exported without specifying an entity filter cannot be loaded into BigQuery._
1. Wait for it to be done with `gcloud datastore operations list | grep done`.
1. [Import it into BigQuery](https://cloud.google.com/bigquery/docs/loading-data-cloud-datastore#loading_cloud_datastore_export_service_data):

    ```
    for kind in Follower Object; do
      bq load --replace --nosync --source_format=DATASTORE_BACKUP datastore.$kind gs://bridgy-federated.appspot.com/stats/all_namespaces/kind_$kind/all_namespaces_kind_$kind.export_metadata
    done
    ```
1. Check the jobs with `bq ls -j`, then wait for them with `bq wait`.
1. [Run the full stats BigQuery query.](https://console.cloud.google.com/bigquery?sq=664405099227:58879d2908824a21b737eee98fff2de8) Download the results as CSV.
1. [Open the stats spreadsheet.](https://docs.google.com/spreadsheets/d/1OtOZ2Rb4EqAGEp9rHziWkyJD4BaRFb_971KjOqMKePA/edit) Import the CSV, replacing the _data_ sheet.
1. Check out the graphs! Save full size images with OS or browser screenshots, thumbnails with the _Download Chart_ button.
