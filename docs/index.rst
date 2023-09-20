Bridgy Fed developer documentation
----------------------------------

Bridgy Fed connects your web site to
`Mastodon <https://joinmastodon.org>`__ and the
`fediverse <https://en.wikipedia.org/wiki/Fediverse>`__ via
`ActivityPub <https://activitypub.rocks/>`__,
`webmentions <https://webmention.net/>`__, and
`microformats2 <https://microformats.org/wiki/microformats2>`__. Your
site gets its own fediverse profile, posts and avatar and header and
all. Bridgy Fed translates likes, reposts, mentions, follows, and more
back and forth. `See the user docs <https://fed.brid.gy/docs>`__ and
`developer docs <https://bridgy-fed.readthedocs.io/>`__ for more
details.

https://fed.brid.gy/

Also see the
`original <https://snarfed.org/indieweb-activitypub-bridge>`__
`design <https://snarfed.org/indieweb-ostatus-bridge>`__ blog posts.

License: This project is placed in the public domain.

Development
-----------

Development reference docs are at
`bridgy-fed.readthedocs.io <https://bridgy-fed.readthedocs.io/>`__. Pull
requests are welcome! Feel free to `ping me in
#indieweb-dev <https://indieweb.org/discuss>`__ with any questions.

First, fork and clone this repo. Then, install the `Google Cloud
SDK <https://cloud.google.com/sdk/>`__ and run
``gcloud components install beta cloud-datastore-emulator`` to install
the `datastore
emulator <https://cloud.google.com/datastore/docs/tools/datastore-emulator>`__.
Once you have them, set up your environment by running these commands in
the repo root directory:

.. code:: sh

   gcloud config set project bridgy-federated
   python3 -m venv local
   source local/bin/activate
   pip install -r requirements.txt

Now, run the tests to check that everything is set up ok:

.. code:: shell

   gcloud beta emulators datastore start --use-firestore-in-datastore-mode --no-store-on-disk --host-port=localhost:8089 --quiet < /dev/null >& /dev/null &
   python3 -m unittest discover

Finally, run this in the repo root directory to start the web app
locally:

.. code:: shell

   GAE_ENV=localdev FLASK_ENV=development flask run -p 8080

If you send a pull request, please include (or update) a test for the
new functionality!

If you hit an error during setup, check out the `oauth-dropins
Troubleshooting/FAQ
section <https://github.com/snarfed/oauth-dropins#troubleshootingfaq>`__.

You may need to change `granary <https://github.com/snarfed/granary>`__,
`oauth-dropins <https://github.com/snarfed/oauth-dropins>`__,
`mf2util <https://github.com/kylewm/mf2util>`__, or other dependencies
as well as as Bridgy Fed. To do that, clone their repo locally, then
install them in “source” mode with e.g.:

.. code:: sh

   pip uninstall -y granary
   pip install -e <path to granary>

To deploy to the production instance on App Engine - if @snarfed has
added you as an owner - run:

.. code:: sh

   gcloud -q beta app deploy --no-cache --project bridgy-federated *.yaml

How to add a new protocol
-------------------------

1. Determine `how you’ll map the new protocol to other existing Bridgy
   Fed protocols <https://fed.brid.gy/docs#translate>`__, specifically
   identity, protocol inference, events, and operations. `Add those to
   the existing tables in the
   docs <https://github.com/snarfed/bridgy-fed/blob/main/templates/docs.html>`__
   in a PR. This is an important step before you start writing code.
2. If the new protocol uses a new data format - which is likely - add
   that format to `granary <https://github.com/snarfed/granary>`__ in a
   new file with functions that convert to/from `ActivityStreams
   1 <https://activitystrea.ms/specs/json/1.0/>`__ and tests. See
   `nostr.py <https://github.com/snarfed/granary/blob/main/granary/nostr.py#L542>`__
   and
   `test_nostr.py <https://github.com/snarfed/granary/blob/main/granary/tests/test_nostr.py#>`__
   for examples.
3. Implement the protocol in a new ``.py`` file as a subclass of both
   `Protocol <https://github.com/snarfed/bridgy-fed/blob/main/protocol.py>`__
   and
   `User <https://github.com/snarfed/bridgy-fed/blob/main/models.py>`__.
   Implement the ``send``, ``fetch``, ``serve``, and ``target_for``
   methods from ``Protocol`` and ``readable_id``, ``web_url``,
   ``ap_address``, and ``ap_actor`` from ``User`` .
4. TODO: add a new usage section to the docs for the new protocol.
5. TODO: does the new protocol need any new UI or signup functionality?
   Unusual, but not impossible. Add that if necessary.
6. Add the new protocol’s logo to ``static/``, use it in
   `templates/user.html <https://github.com/snarfed/bridgy-fed/blob/main/templates/user.html>`__.

Stats
-----

I occasionally generate stats and graphs of usage and growth via
BigQuery, `like I do with
Bridgy <https://bridgy.readthedocs.io/#stats>`__. Here’s how.

1. `Export the full datastore to Google Cloud
   Storage. <https://cloud.google.com/datastore/docs/export-import-entities>`__
   Include all entities except ``MagicKey``. Check to see if any new
   kinds have been added since the last time this command was run.

   ::

      gcloud datastore export --async gs://bridgy-federated.appspot.com/stats/ --kinds Follower,Object

   Note that ``--kinds`` is required. `From the export
   docs <https://cloud.google.com/datastore/docs/export-import-entities#limitations>`__:
   > *Data exported without specifying an entity filter cannot be loaded
   into BigQuery.*

2. Wait for it to be done with
   ``gcloud datastore operations list | grep done``.

3. `Import it into
   BigQuery <https://cloud.google.com/bigquery/docs/loading-data-cloud-datastore#loading_cloud_datastore_export_service_data>`__:

   ::

      for kind in Follower Object; do
        bq load --replace --nosync --source_format=DATASTORE_BACKUP datastore.$kind gs://bridgy-federated.appspot.com/stats/all_namespaces/kind_$kind/all_namespaces_kind_$kind.export_metadata
      done

4. Check the jobs with ``bq ls -j``, then wait for them with
   ``bq wait``.

5. `Run the full stats BigQuery
   query. <https://console.cloud.google.com/bigquery?sq=664405099227:58879d2908824a21b737eee98fff2de8>`__
   Download the results as CSV.

6. `Open the stats
   spreadsheet. <https://docs.google.com/spreadsheets/d/1OtOZ2Rb4EqAGEp9rHziWkyJD4BaRFb_971KjOqMKePA/edit>`__
   Import the CSV, replacing the *data* sheet.

7. Check out the graphs! Save full size images with OS or browser
   screenshots, thumbnails with the *Download Chart* button.
