# vmray-sekoia

VMRay1 integration for Sekoia.io: a Sekoia automation module and the playbooks that use it. A playbook gets a file into the run's storage (fetched from SentinelOne), VMRay detonates it, the full VMRay report is posted on the alert as a comment with screenshots, and the indicators found are pushed to a Sekoia IOC collection.

## Layout

| Path | Contents |
|---|---|
| [`VMRay1/`](VMRay1/) | The automation module. [`VMRay1/CONFIGURE.md`](VMRay1/CONFIGURE.md) covers setup; [`VMRay1/README.md`](VMRay1/README.md) covers the actions, the playbooks, the comment layout, known limitations and development. |
| [`VMRay1/CHANGELOG.md`](VMRay1/CHANGELOG.md) | Release history. |
| [`Test/`](Test/) | A second, separate integration, "Test", with one action, Download File, that saves a file (for example a zip) from a URL in the playbook run's storage so every VMRay1 action can be tried on it. [`Test/CONFIGURE.md`](Test/CONFIGURE.md) covers setup. |
| [`playbooks/templates/`](playbooks/templates/) | The playbooks that use the module, listed in `playbooks.json`. |

## Playbooks

| File | What it is |
|---|---|
| `playbooks/templates/test_download_and_scan_archive.json` | "Test: Download and scan an archive (all VMRay1 actions)" — Manual trigger. The Test integration downloads a nested zip with several child files and every VMRay1 action runs on it. |
| `playbooks/templates/vmray1_scan_url.json` | "VMRay1: Scan URL" — Manual trigger. Scans a URL (the EICAR test file by default); needs no EDR. |
| `playbooks/templates/vmray1_sentinelone_manual_tmp.json` | "VMRay1: Manual - Scan SentinelOne file (TMP test)" — Manual trigger; same steps, run by an analyst on an alert. For testing. |
| `playbooks/templates/vmray1_sentinelone_demo.json` | "VMRay1: Alert Created - Scan SentinelOne file" — Alert Created trigger. SentinelOne fetches the threat's file from the endpoint, VMRay analyses it (Get Submission Result waits for the analysis), and the report and the suspicious child samples are posted on the alert. Carries this tenant's trigger and SentinelOne account IDs. |

Select your VMRay1 account on the VMRay1 nodes and set a real `ioc_collection_id` after importing either one.
