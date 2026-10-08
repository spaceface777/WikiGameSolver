## WikiGameSolver


A script that calculates the minimum number of link clicks required to get from one Wikipedia entry to another.  
Online version available at https://wiki.spaceface.dev.

NOTE: requires an adapted Wikipedia dump. You can [download one from the releases page](https://github.com/spaceface777/WikiGameSolver/releases), or build your own.

## Monthly sidecars

The workflow publishes graphs to R2 and GitHub Releases. It publishes `<language>.bin.meta.zst` to R2, but not GitHub Releases. It also saves the sidecar as an optional CI artifact with seven-day retention. CI artifact upload depends on available artifact storage. The sidecar retains all source identities and siteinfo, including pages excluded from the graph. It binds the source archive, raw graph, and compressed graph with SHA-256 hashes.

The new sidecar format and static-wikitext parser policy start at version 1. The existing RAW WIKI v2 graph format stays unchanged. The parser uses Unicode title rules and static links, not template expansion or every rendered anchor.

Consumers must verify the bound hashes before they use a graph and sidecar together. The source directory date is not an atomic Wikipedia snapshot.
