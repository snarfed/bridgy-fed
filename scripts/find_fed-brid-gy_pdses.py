"""Searches a PLC directory JSON Lines export for DIDs with PDS fed.brid.gy."""
import json
import sys

fed = {}  # maps DID to domain

with open(sys.argv[1]) as f:
    for line in f:
        entry = json.loads(line)
        did = entry['did']
        op = entry['operation']
        pds = op['services'].get('atproto_pds', {}).get('endpoint').rstrip('/')
        if pds == 'https://fed.brid.gy':
            fed[did] = op['alsoKnownAs'][0].removeprefix('at://')
        elif pds == 'https://atproto.brid.gy':
            fed.pop(did, None)

for did, domain in fed.items():
    print(did, domain)
