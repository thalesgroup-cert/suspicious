# Bundled connector logos

Logos are bundled so the settings page never fetches an image at runtime (air-gapped installs work). They are
used only to identify the integration next to its name; every mark remains the property of its owner and no
endorsement is implied. `smtp_notify` and `ai_narration` have no single brand and use a neutral icon instead.
All files were retrieved on 2026-10-19 by `curl` from raw.githubusercontent.com. Commit hashes pin the exact
revision. Confirm brand usage before the final merge.

| File | Brand | Source URL | Licence | Retrieved | Modification |
|---|---|---|---|---|---|
| `misp-logo.svg` | MISP | https://github.com/MISP/MISP/blob/fc99c9e3fc85beddc6ef18835359f3c8b7f44608/INSTALL/logos/misp-logo.svg | AGPL-3.0 (repository licence) | 2026-10-19 | Inkscape/sodipodi metadata and attributes (including `-inkscape-font-specification`), comments, unused ids and fixed mm width/height removed; paths and `viewBox` untouched. |
| `chroma-logo.svg` | Chroma | https://github.com/chroma-core/chroma/blob/ddc17cd7c508f15f237c965e74e536ff64396ddb/docs/mintlify/images/favicon.svg | Apache-2.0 (repository licence) | 2026-10-19 | id and fixed width/height removed; the Streamline `<desc>` attribution is kept; paths and `viewBox` untouched. The file carries a Streamline export marker, so its own terms may differ from the repository licence. |
| `elasticsearch-logo.svg` | Elasticsearch | https://github.com/simple-icons/simple-icons/blob/c71c69e3a27e4436936b831c72643e6513b9f49b/icons/elasticsearch.svg | CC0-1.0 (Simple Icons icon data); the mark is a trademark of Elasticsearch B.V. (brand guidelines: https://www.elastic.co/brand) | 2026-10-19 | `<title>` removed; fill set to the brand colour `#005571` from the Simple Icons data (the file has none, so it would render black). Path and `viewBox` unchanged; the connector tile is white, which keeps the dark mark legible on dark themes. |
| `thehive-logo.png` | TheHive | https://github.com/TheHive-Project/TheHive/blob/d390a0316ccd7780df6a49eccc773e5c28b43cc2/images/thehive-logo.png | AGPL-3.0 (repository licence; repository is archived) | 2026-10-19 | Original is the 1000x260 wordmark. Cropped to the bee/hexagon emblem (left 188x215 px region) and resized to 128x128 with transparent padding. |
| `watcher-logo.png` | Watcher | https://github.com/thalesgroup-cert/Watcher/blob/e0c4cc6e1be6d3f6206ca14776b847cdf5b1d252/Watcher/Watcher/frontend/static/img/round-logo-fav.png | AGPL-3.0 (repository licence) | 2026-10-19 | Resized from 1631x1626 to 128x128. |
