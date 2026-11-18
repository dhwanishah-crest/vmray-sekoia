# vmray-sekoia

VMRay1 integration for Sekoia.io: a Sekoia automation module and the playbooks that use it. A playbook gets a file into the run's storage (downloaded from a URL, or fetched from SentinelOne), VMRay detonates it, the full VMRay report is posted on the alert as a comment with screenshots, and the indicators found are pushed to a Sekoia IOC collection.

## Layout

| Path | Contents |
|---|---|
| [`VMRay1/`](VMRay1/) | The automation module. [`VMRay1/CONFIGURE.md`](VMRay1/CONFIGURE.md) covers setup; [`VMRay1/README.md`](VMRay1/README.md) covers the actions, the playbooks, the comment layout, known limitations and development. |
| [`VMRay1/CHANGELOG.md`](VMRay1/CHANGELOG.md) | Release history. |
| [`playbooks/templates/`](playbooks/templates/) | The playbooks that use the module, listed in `playbooks.json`. |

## Playbooks

| File | What it is |
|---|---|
| `playbooks/templates/vmray1_scan_file_from_url.json` | "VMRay1: Scan file from URL" — Manual trigger. Downloads a file from a URL and scans it; use it to test the module. |
| `playbooks/templates/vmray1_sentinelone_demo.json` | "VMRay1: Alert Created - Scan SentinelOne file" — Alert Created trigger. SentinelOne fetches the threat's file from the endpoint and VMRay scans it. Carries this tenant's trigger and SentinelOne account IDs. |

Select your VMRay1 account on the VMRay1 nodes and set a real `ioc_collection_id` after importing either one.
