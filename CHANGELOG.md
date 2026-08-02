# Changelog

## Unreleased

### nexthop: add support for Resilient Next-hop Groups

**Background (what already existed upstream)**

The upstream library previously had only *basic* nexthop support (from `Add a basic support for nexthop`):
- Low-level nexthop primitives in the `nl` package (`nl.Nhmsg`, `NewNexthopRequest`).
- `NexthopAdd` / `NexthopDel` / `NexthopList` / `NexthopReplace` APIs.
- Only single nexthops were supported, serializing `NHA_ID`, `NHA_BLACKHOLE`, `NHA_OIF`, `NHA_GATEWAY`, and `Protocol`.
- `NHID` field on `Route` to attach an existing nexthop object to a route.
- No notion of *groups*: `Nexthop` had no `Group`, `GroupType`, or `ResGroup` fields, so multipath and resilient nexthop groups (`ip nexthop ... group ... type res`) could not be created or parsed.

**What this PR brings**

- New API types:
  - `NexthopGroupMpath{ID, Weight}` — a member (nexthop ID + relative weight, 1–256; 0 treated as 1).
  - `NexthopResGroup{Buckets, IdleTimer, UnbalancedTimer, UnbalancedTime}` — resilient-group configuration.
  - Group-type constants `NEXTHOP_GRP_TYPE_MPATH` and `NEXTHOP_GRP_TYPE_RES`.
- Extended `Nexthop` struct with `Group []NexthopGroupMpath`, `GroupType uint16`, and `ResGroup *NexthopResGroup`.
- Serialization/deserialization of the new attributes: `NHA_GROUP` (with weight encoding `wire = weight - 1`), `NHA_GROUP_TYPE`, and the nested `NHA_RES_GROUP` (`NHA_RES_GROUP_BUCKETS`, `NHA_RES_GROUP_IDLE_TIMER`, `NHA_RES_GROUP_UNBALANCED_TIMER`, `NHA_RES_GROUP_UNBALANCED_TIME`), where timers are converted to/from kernel `clock_t` units.
- New `nl` package constants: `NHA_RES_GROUP`, `NHA_RES_BUCKET`, `NHA_RES_GROUP_*`, `NHA_RES_GROUP_PAD`.
- Input validation in `prepareNewNexthop` (res-group requires `NEXTHOP_GRP_TYPE_RES`; non-empty group for a set group type) and family derivation (`FAMILY_ALL`) for group nexthops.
- `Handle.RetryInterrupted()` option to auto-retry interrupted dumps.
- New example `examples/resilient-nexthop-group` reproducing `ip nexthop add id <N> group <members> type res buckets <n> idle_timer <s> unbalanced_timer <s>`.

## 1.0.0 (2018-03-15)

Initial release tagging