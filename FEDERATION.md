# Federation

[Bridgy Fed](https://fed.brid.gy/) is a bridge across decentralized social network protocols. It tries to translate between protocols fully bidirectionally, as completely and with as high fidelity as possible. It uses [granary](https://granary.io/) to translate between different protocols' data formats.

Bridgy Fed currently supports the [IndieWeb](https://indieweb.org/), the [Fediverse](https://en.wikipedia.org/wiki/Fediverse), and [Bluesky](https://bsky.social/). [Nostr](https://nostr.com/) and [Farcaster](https://www.farcaster.xyz/) are on the roadmap for the future.

This document describes, at a high level, how Bridgy Fed supports and translates between the different protocols it suports. It's based on [FEP-67ff](https://codeberg.org/silverpill/feps/src/branch/main/67ff/fep-67ff.md).


## Background

Bridgy Fed's documentation describes much of its details. Here are some relevant sections:

* [How does this handle behavior differences between networks?](https://fed.brid.gy/docs#behavior-mismatches)
* [How does this handle formatting differences between networks?](https://fed.brid.gy/docs#format-mismatches)
* [How do the different protocols compare?](https://fed.brid.gy/docs#compare)
* [How are the different protocols translated?](https://fed.brid.gy/docs#translate)
* [How are activities routed?](https://fed.brid.gy/docs#router)
* [What are Bridgy Fed's product and engineering values?](https://fed.brid.gy/docs#values)


## Supported federation protocols and standards

* [IndieWeb](https://indieweb.org/)
  * [microformats2](https://microformats.org/wiki/microformats2)
  * [Webmention](https://webmention.net/)
* [Atom](http://www.atomenabled.org/), [RSS](https://www.rssboard.org/)
* [Fediverse](https://en.wikipedia.org/wiki/Fediverse)
  * [ActivityPub](https://www.w3.org/TR/activitypub/) (Server-to-Server)
  * [WebFinger](https://webfinger.net/)
  * [HTTP Signatures](https://swicg.github.io/activitypub-http-signature/)
  * [NodeInfo](https://nodeinfo.diaspora.software/)
* [Bluesky](https://bsky.social/)
  * [AT Protocol](https://atproto.com/)


## IndieWeb

Bridgy Fed accepts incoming [webmentions](https://webmention.net/), fetches remote web pages, parses their HTML for [microformats2](https://microformats.org/wiki/microformats2), and handles the contained data. It also sends outbound webmentions and translates and serves data from other networks into HTML with microformats2. It supports microformats2 profiles (`h-cards`), posts, replies, likes, reposts, deletes (including both serving and handling HTTP 410), hashtags, mentions.


## Atom, RSS

Beyond IndieWeb sites, Bridgy Fed also supports reading posts from web sites via [Atom](http://www.atomenabled.org/) and [RSS](https://www.rssboard.org/) feeds.


## Fediverse

Bridgy Fed tries to be a relatively full featured fediverse implementation, including ActivityPub server-to-server, WebFinger, and HTTP Signatures. It translates [ActivityStreams 2](https://www.w3.org/TR/activitystreams-core/) objects and activities to and from other networks' data formats.

Supported AS2 object types: `Application`, `Article`, `Audio`, `Event`, `Flag`, `Image`, `Link`, `Mention`, `Note`, `Organization`, `Person`, `Place`, `Service`, `Video`

Supported AS2 object types: `Accept`, `Announce`, `Block`, `Create`, `Delete`, `Follow`, `Like`, `Reject`, `Undo` (of some activities), `Update`

Bridgy Fed doesn't require [authorized fetch](https://www.w3.org/wiki/ActivityPub/Primer/Authentication_Authorization#Authorized_fetch), ie signed HTTP GETs for AS2 objects and activities, but it does attach valid HTTP Signatures to its own outbound GETs to other servers.


### Supported FEPs

Current:

* [FEP-f1d5: NodeInfo in Fediverse Software](https://codeberg.org/fediverse/fep/src/branch/main/fep/f1d5/fep-f1d5.md)
* [FEP-2677: Identifying the Application Actor](https://codeberg.org/fediverse/fep/src/branch/main/fep/2677/fep-2677.md)

Planned:

* [FEP-fffd: Proxy Objects](https://codeberg.org/fediverse/fep/src/branch/main/fep/fffd/fep-fffd.md) [GitHub](https://github.com/snarfed/bridgy-fed/issues/543)
* [FEP-7628: Move actor](https://codeberg.org/fediverse/fep/src/branch/main/fep/7628/fep-7628.md) [GitHub](https://github.com/snarfed/bridgy-fed/issues/330)


## Bluesky / AT Protocol

Bridgy Fed's support for [Bluesky](https://bsky.social/) is based on [arroba](https://arroba.readthedocs.io/), a fully independent implementation of the [AT Protocol](https://atproto.com/), and [lexrpc](https://lexrpc.readthedocs.io/), a related independent implementation of [XRPC](https://atproto.com/specs/xrpc) and [Lexicon](https://atproto.com/guides/lexicon).

Bridgy Fed is a federated AT protocol [PDS](https://atproto.com/guides/overview#federation), ie user data server. It translates data to/from the [`bsky.app` lexicon](https://atproto.com/guides/overview#interoperation) (data model) and serves it to the main [`bsky.network` relay](https://docs.bsky.app/docs/advanced-guides/federation-architecture), which sends it onward to the main AppView and from there to user-facing clients like [bsky.app](https://bsky.app/).
