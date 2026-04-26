# MediaNav Toolbox Overview

A Linux/Python replacement for the Windows-only Dacia MediaNav Evolution Toolbox. Reverse-engineers the NaviExtras wire protocol to update maps, POIs, speed cameras, and voice packs on Dacia/Renault MediaNav head units. Also includes the first public decode of the NNG/iGO proprietary map format, with tools to convert OpenStreetMap data into NNG `.fbl` map files.

## Key Documents

- [README.md](../../README.md) — Project overview, quick start, CLI usage, supported devices, and architecture summary.
- [docs/reverse-engineering.md](../../docs/reverse-engineering.md) — Full reverse engineering record: protocol architecture, approaches tried, tools built, and current status.
- [docs/chain-encryption.md](../../docs/chain-encryption.md) — Wire format spec for delegated requests, with construction recipe and test vectors.
- [docs/serializer.md](../../docs/serializer.md) — Deep technical reference for the igo-binary serializer internals (query and body encoding).
- [docs/mapformat.md](../../docs/mapformat.md) — 1,800+ line specification of the NNG/iGO map format: encryption, container structure, coordinate encoding, road classes, and more.
- [docs/license-system.md](../../docs/license-system.md) — How map content is protected: RSA-signed `.lyc` licenses, SWID binding, and the activation flow.
