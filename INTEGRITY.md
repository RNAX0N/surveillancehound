# Integrity record

This file exists so that tampering shows up on an ordinary audit. It
records, at each milestone, the sha256 of the files that carry the
network-facing and trust-bearing logic, together with the commit and
tree they belong to.

A copy of every block below is also written to
`~/Development/mailbox-agents/surveillancehound-relay-agent-mode_2026-10-15.md`,
outside this repository. Two records that disagree are the signal; a
single record that an attacker can rewrite in the same commit is not.

## How to verify

Check out the commit a block names, then feed **that block only** to
`sha256sum -c`. Feeding the whole file would check every milestone's
hashes against one checkout, and all but one block would fail by
design:

```bash
git checkout <commit>
sha256sum -c <<'EOF'
<paste the hash lines from that block>
EOF
git rev-parse HEAD HEAD^{tree}   # must equal the block's commit/tree
```

The hashes are of the working-tree files, so they are reproducible by
anyone with a checkout and no tooling beyond `sha256sum`.

## Milestones

### `ee2ab22` — relay/agent mode, 31 review rounds (2026-10-17)

Both reviewers APPROVED at `96dbcd3`; this commit closes their
follow-ups. 8/8 verification suites green. Nothing pushed to `origin`.

```
ca11aaeeeabc750899d36c258dea475c090b95e1fdd88e9211b324fee25740b8  src/surveillancehound/relay.py
082cb8f974cfcb93e3763851055f4c3a328e2a9ff9e0693b6dcc4f42a71c4389  src/surveillancehound/ingest.py
8c1872b4466a52693b0562d75d88b9258ab30f7c8eafc0742fbb0efa9a20586a  src/surveillancehound/validate.py
08af1cf725dd56003b3e8569f75908530f61e25659c49570cb972eadabd38865  src/surveillancehound/store.py
c990d34d19fd5c639e2c64cf158b1204a54ac6a56a215434fd72fcb07cdc44b7  src/surveillancehound/cli.py
b047e6439483370c5cdd55741a87dc3149ebfe004a78443b6f1cc1b5b16739c5  tests/verify_relay.py
35c72828d1d8fb0b6491a2eb9e42a1313a9969651f783b98a06745d2c90491ff  deploy/agent/README.md
963924573c5bcebfa2f7ae408e4525aa6947f0f35257650f206b01eaa5ba06b0  hound.toml.example
```

- commit: `ee2ab22c63e8eecc7bb02769bdc2ab90a5417f63`
- tree:   `305d664df66e1bc20b2911c6eea955161f9eef7e`

> As with every block here, the hashes are of the tree *before* this
> file recorded them. `git show --stat ee2ab22` confirms the listed
> files are unchanged by the commit that adds the block.

### `0fb1b86` — relay/agent mode complete (2026-10-17)

Multi-sensor relay: agent spools signed observations and ships them
over pinned TLS to a collector. 27 review rounds, 8/8 verification
suites green. Nothing pushed to `origin` at the time of writing.

```
35c5f89fbea83ae647ad5fd822b7f9e88f38dfa64e86be7eb49adbec7d9576e2  src/surveillancehound/relay.py
04b5f55e82611b032c61b33c0870377ad17cee44df99344a344ecc5aebb85450  src/surveillancehound/ingest.py
8c1872b4466a52693b0562d75d88b9258ab30f7c8eafc0742fbb0efa9a20586a  src/surveillancehound/validate.py
08af1cf725dd56003b3e8569f75908530f61e25659c49570cb972eadabd38865  src/surveillancehound/store.py
9b74dc1080fe50eec0b37496eb1744baa1cc2fd90541248d7b84ade00cab052d  src/surveillancehound/cli.py
a9faa984fe0b78d6fb72274a180c97adc5491b8556dbacf6b8c2adc8ac395931  tests/verify_relay.py
5fc965a69c7d52cd22a20bf00440b6ef5943b8298efe4370e580fea54f13b85e  deploy/agent/README.md
963924573c5bcebfa2f7ae408e4525aa6947f0f35257650f206b01eaa5ba06b0  hound.toml.example
```

- commit: `0fb1b8689b568bca157a17d301de86f66a085679`
- tree:   `941453e06e09e61d82084a95531cf42528721cda`

> The hashes above are of the tree *before* this file was added, since
> `INTEGRITY.md` cannot contain its own hash. The commit id is therefore
> the one that introduces this block, and the listed files are unchanged
> by it — confirm with `git show --stat <commit>`.

### `82ca79c` — round 26 LOWs closed (2026-10-16)

```
d4d8bc1cdfbaea6b80671776f1adbc98181868346a2679a5317a35a778850d78  src/surveillancehound/relay.py
332e4b29737de38478db28787480b3977b5ccb97f77faea73a6515ef68b0cd0a  src/surveillancehound/ingest.py
08af1cf725dd56003b3e8569f75908530f61e25659c49570cb972eadabd38865  src/surveillancehound/store.py
b7b5ca91c559e9e3670bf0876dc3e4347baa66073a9598464b111e7f04e08228  src/surveillancehound/cli.py
95d942f15e2107aa82b673f060760dd9b5a0ec260514fab643d9f1b14525cd3b  tests/verify_relay.py
352f782834ab9da2f953189e022d951c1eacf67bf6bd4715a19fe7fc3ea2d537  deploy/agent/README.md
963924573c5bcebfa2f7ae408e4525aa6947f0f35257650f206b01eaa5ba06b0  hound.toml.example
```

- commit: `82ca79c0ff33cc93d492aa8725e245ce5dd01e40`
- tree:   `6182858502ed7d8da81dda344ee77dc70e7b749f`
