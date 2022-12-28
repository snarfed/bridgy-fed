<img src="https://raw.github.com/snarfed/bridgy-at/main/static/bridgy_fed_logo.png" width="120" /> [Bridgy Fed](https://fed.brid.gy/) [![Circle CI](https://circleci.com/gh/snarfed/bridgy-at.svg?style=svg)](https://circleci.com/gh/snarfed/bridgy-at) [![Coverage Status](https://coveralls.io/repos/github/snarfed/bridgy-at/badge.svg?branch=main)](https://coveralls.io/github/snarfed/bridgy-at?branch=main)
===

Early prototype of bridging the [IndieWeb](https://indieweb.org/) to [AT Protocol](https://atproto.com/).

License: This project is placed in the public domain.


### TODO

* [CID](https://atproto.com/guides/data-repos#data-layout) algorithm for web site posts.
* Decide whether to mirror the [`app.bsky` lexicons](https://github.com/bluesky-social/atproto/tree/main/lexicons/app/bsky) in this repo or [fetch them dynamically via `getSchema`](https://atproto.com/guides/lexicon#schema-distribution), which isn't live on [bsky.app](https://bsky.app/) yet.
* Test against the [atproto `pds` package](https://github.com/snarfed/atproto/tree/main/packages/pds), which includes their server-side `app.bsky` implementation.
