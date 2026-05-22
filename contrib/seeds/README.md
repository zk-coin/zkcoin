# Seeds

Utilities in this directory generate the `seeds.txt` list that can be compiled
into the client, see [src/chainparamsseeds.h](/src/chainparamsseeds.h) and the
other utilities in [contrib/seeds](/contrib/seeds).

zkCoin public release builds must not generate DNS or fixed seeds from
inherited Litecoin seed data. Public `main` and `testnet` currently clear DNS
and fixed seeds and fail launch readiness until zkCoin-specific seed
infrastructure exists.

Before enabling public seeds:

- Generate crawler output from the intended zkCoin public network.
- Keep `PATTERN_AGENT` in `makeseeds.py` aligned with accepted zkCoin node
  versions, and remove old versions when service-flag defaults change.
- Run `makeseeds.py` against the zkCoin crawler output to produce
  `nodes_main.txt` or the equivalent network-specific node list.
- Run `generate-seeds.py` only from zkCoin node lists, then review the resulting
  `src/chainparamsseeds.h` diff before enabling fixed seeds.

Example flow once zkCoin crawler output exists:

```bash
python3 makeseeds.py < zkcoin-seeds-main.txt > nodes_main.txt
python3 generate-seeds.py . > ../../src/chainparamsseeds.h
```

## Dependencies

Ubuntu:

```bash
sudo apt-get install python3-dnspython
```
