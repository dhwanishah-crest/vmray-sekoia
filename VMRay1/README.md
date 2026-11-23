# VMRay1

VMRay Platform - Agentless hypervisor-based sandbox for malware detonation, VTI scoring and IOC extraction.

VMRay1 scans **files and URLs**: a Sekoia.io playbook looks up file hashes in VMRay, detonates a URL, or gets a file into the run's storage (fetched from an EDR such as SentinelOne) and detonates it in VMRay, builds the full VMRay report, posts it on the alert as a comment (with screenshots), and pushes the indicators found to a Sekoia IOC collection. It installs next to the original VMRay integration and does not replace it.

## Configuration

See [CONFIGURE.md](CONFIGURE.md): requirements, creating the VMRay API key, connecting the account in Sekoia.io and a typical playbook chain.

## How it works

```
hashes ──► GetSamplesByHash ──► sample_ids ─────┐
URL ─────► SubmitUrlSample ───► submission_ids ─┤
                                                 ├─► BuildReport ──► report_path ─┬─► RenderReport ──► comment + screenshot comments
SentinelOne malware ──────► files ──► SubmitFileSample ─► submission_ids ─┘    └─► ExtractIocs ──────► IOC collection
```

1. **Find or create samples.** `GetSamplesByHash` looks hashes up in VMRay's existing analyses (no quota). `SubmitUrlSample` detonates a URL and waits for the result (consumes quota).
2. **Or put a file in the run's storage.** An EDR action such as SentinelOne's "Get malwares from threat" fetches it from the endpoint and returns `files`, a list of `{"path": ...}`.
3. **Detonate it.** `SubmitFileSample` uploads each file to VMRay and waits for the result (consumes quota).
4. **Build the report.** `BuildReport` fetches everything VMRay knows about each sample and writes the report to a JSON file on the run's storage. Only the file's path travels between nodes: a report with screenshots is far larger than Sekoia accepts as an action argument (SYM216).
5. **Use the report.** `RenderReport` turns it into the alert comment; `ExtractIocs` turns it into indicators for an IOC collection. Neither calls VMRay or Sekoia.

## Actions

### `GetSamplesByHash` - Get Samples By Hash

Looks up SHA256, SHA1 or MD5 hashes in VMRay's existing analyses and returns every matching sample. Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `hashes` (File hashes) | required | list of SHA256, SHA1 or MD5 hashes to look up; duplicates ignored, no quota used |

**Outputs:** `found` (at least one sample) / `not_found` (none). **Results:** `sample_ids`, `samples`, `not_found` (hashes VMRay has never analysed), `errors` (per hash: invalid value or lookup failure).

### `GetChildSamples` - Get Child Samples

Lists the samples VMRay found inside a sample: the files of an archive, the attachments and links of an email, the files a URL downloaded. VMRay analyzes each of them as a sample of its own, so each has its own verdict and may have children of its own. Starts from a sample (or the sample of a submission) and follows `sample_child_sample_ids` one `GET /sample/{id}` per child. Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `sample_id` (Sample ID) | | the parent sample, e.g. `sample_ids` of Get Samples By Hash |
| `submission_id` (Submission ID) | | resolved to its sample; used when `sample_id` is empty. One of the two is required |
| `max_depth` (Max depth) | `10` | levels of children to follow, 1 to 10: 1 lists only the direct children |
| `min_verdict` (Minimum verdict) | empty | `clean` (every child with a known verdict), `suspicious` (suspicious and malicious) or `malicious`; empty lists every child. Any other value is an error |

A child that `min_verdict` leaves out is still searched for children of its own: a clean archive can hold a malicious file. A sample is listed once, however many parents name it.

**Outputs:** `has_children` (at least one child is listed) / `no_children`, so a playbook can skip the rest. **Results:** `children` (nearest levels first; each has `sample_id`, `parent_sample_id`, `depth`, `name`, `type`, `md5`, `sha1`, `sha256`, `verdict`, `verdict_reason`, `vti_score`, `webif_url`, `child_count`), `sample_ids` (input for Build Report), `child_count`, `total_child_count` (before `min_verdict`), `sample_id` (the parent), `errors` (a child VMRay could not return, by `child_sample:<id>`).

### `GetSampleRelations` - Get Sample Relations

Lists the relation records VMRay keeps between a sample and the samples found inside it (`GET /rest/sample_relation/sample/{id}`, or `/submission/{id}`). The Console shows the relation type there (for example "Embedded File"). Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `sample_id` (Sample ID) | | the relations that involve this sample |
| `submission_id` (Submission ID) | | the relations created by this submission; used when `sample_id` is empty. One of the two is required |

**Outputs:** `found` (VMRay returned at least one relation) / `not_found`. **Results:** `relations` (the records exactly as VMRay sends them), `relation_count`, `related_sample_ids` (every other sample named by a `*sample_id` field of the records).

VMRay's API reference lists these endpoints but not the fields of a record, so the records are passed through untouched and only `related_sample_ids` reads them. Use `GetChildSamples` for a tree of children with verdicts; use this for the relation type.

### `GetChildSampleReport` - Get Child Sample Report

Builds the full report of one child sample, the same report `BuildReport` writes (analyses, VTIs, MITRE ATT&CK, IOCs, classifications, threat names, screenshots, then the child's own children). `BuildReport` given the child's `sample_id` does the same; this action adds the check that the child belongs to the parent, so a wrong ID fails instead of reporting on an unrelated sample.

| Argument | Default | Notes |
|---|---|---|
| `parent_sample_id` | required | the sample the child was found in, e.g. `sample_id` of Get Child Samples |
| `child_sample_id` | required | the child to report on, e.g. one of the `sample_ids` of Get Child Samples; it must be in the parent's tree (up to 10 levels) |
| `max_recursion_depth` | `10` | how deep the child's own children are built, at most 10; `0` disables recursion |
| `ioc_severity_filter`, `analysis_verdict_filter`, `include_screenshots` | as in Build Report | |

**Results:** `report_path`, `sample_ids`, `errors`, as for Build Report, so `RenderReport` and `ExtractIocs` take it unchanged.

### `SubmitUrlSample` - Submit URL Sample

Submits a URL and polls every resulting submission until it finishes.

| Argument | Default | Notes |
|---|---|---|
| `sample_url` | required | the URL to detonate |
| `reanalyze` | `true` | re-analyze known samples on submission |
| `tags` | `["sekoia"]` | tags to attach to the sample |
| `shareable` | `false` | share the sample's hash with VirusTotal |
| `max_recursive_samples` | `10` | maximum amount of recursive samples analyzed, at most 10; `0` disables recursion |
| `query_retry_wait` | `10` | seconds to wait before trying to fetch the results |
| `timeout` | `1800` | seconds to wait for every submission to finish, then the `timed_out` branch |
| `analyzer_mode`, `max_jobs`, `enable_reputation`, `enable_whois`, `known_malicious`, `known_benign`, `analysis_timeout`, `net_scheme_name` | empty | VMRay submission options; empty ones are not sent, so the VMRay user's analyzer settings apply |

There are no archive settings (archive password, compound sample): they only apply to submitted files, and this action submits URLs. `timeout` is how long the action waits; the analysis's own timeout is `analysis_timeout`.

**Outputs:** `completed` / `timed_out` / `submission_failed`. **Results:** `submission_ids`, `sample_ids`, `submissions`, `pending_submission_ids` (still running at the timeout), `errors` (VMRay's reasons for a rejected submission).

### `SubmitFileSample` - Submit File Sample

Uploads files from the playbook run's storage (`POST /sample/submit` with `sample_file`) and polls every resulting submission until it finishes. Built for SentinelOne's "Get malwares from threat", which fetches a threat's file(s) from the endpoint, decrypts them and writes them to the storage named by SHA-1.

| Argument | Default | Notes |
|---|---|---|
| `files` | required | paths in the playbook run's storage. Takes another action's output as is: a list of `{"path": ...}` objects or of paths, or a single one. Duplicates are submitted once |
| `reanalyze` | `true` | re-analyze known samples on submission |
| `tags` | `["sekoia"]` | tags to attach to the sample |
| `shareable` | `false` | share the sample's hash with VirusTotal |
| `max_recursive_samples` | `10` | maximum amount of recursive samples analyzed, at most 10; `0` disables recursion |
| `query_retry_wait` | `10` | seconds to wait before trying to fetch the results |
| `timeout` | `1800` | seconds to wait for every submission to finish, then the `timed_out` branch |
| `analyzer_mode`, `max_jobs`, `enable_reputation`, `enable_whois`, `known_malicious`, `known_benign`, `analysis_timeout`, `net_scheme_name` | empty | VMRay submission options; empty ones are not sent, so the VMRay user's analyzer settings apply |

Each file is submitted on its own and sent under its storage-path name; VMRay detects its type from the content. A path outside the storage (absolute, or with `..`), a missing or empty file, and a file VMRay refuses are listed in `errors` with their `file`, and the other files still go through. No archive settings: the files arrive already extracted.

**Outputs:** `completed` / `timed_out` / `submission_failed` (no file could be submitted, or every submission failed). **Results:** `submission_ids`, `sample_ids`, `submissions`, `pending_submission_ids` (still running at the timeout), `failed_submission_ids`, `timed_out`, `errors`, `submitted_files`.

### `StartFileSubmission` / `StartUrlSubmission` - Start File Submission, Start URL Submission

The same upload as `SubmitFileSample` and `SubmitUrlSample`, but they **return at once** instead of waiting for the analysis. They take the same inputs as those two, without `query_retry_wait` and `timeout` (there is nothing to wait for), and send the same form to VMRay. Each file is still submitted on its own, so a file that cannot be read or that VMRay refuses is listed in `errors` while the others go through. Consumes quota, like the waiting actions.

**Outputs:** `submitted` (VMRay started at least one submission) / `submission_failed`. **Results:** `submission_ids` (started, not finished: input for `CheckSubmissionStatus`), `submitted` (bool), `errors`, and for files `submitted_files`.

### `CheckSubmissionStatus` - Check Submission Status

One look at whether submissions have finished: a single `GET /submission/{id}` for each ID, with no waiting and no loop. Takes the `submission_ids` of either Start action, or of `SubmitFileSample` / `SubmitUrlSample`. Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `submission_ids` | required | one ID or a list; duplicates are checked once |

**Outputs:**
- `completed`: nothing is running and at least one submission finished without error. `submission_ids` and `sample_ids` are ready for `BuildReport`.
- `pending`: at least one is still running, or could not be checked this time (`errors` says why). The submissions that already finished are in the results too.
- `failed`: every submission finished with an error.

**Results:** `all_finished`, `submissions`, `submission_ids` and `sample_ids` (finished without error), `pending_submission_ids`, `failed_submission_ids`, `errors`.

A submission that cannot be checked stays pending instead of failing, because the next check may work. When not one of them could be checked (a wrong API key, VMRay down) the action fails, so a playbook never reads "pending" when nothing was looked at.

**Using them in a playbook.** Sekoia has no loop that waits, but its Utils module has a `Wait` action (`duration` in seconds, up to 3600). A chain that does not hold one run open for the whole analysis: `Start File Submission` → `Wait` (say 120 s) → `Check Submission Status` → `completed` goes on to `Build Report`; `pending` goes to another `Wait` → `Check Submission Status`, repeated a fixed number of times, then a comment that the analysis is still running. `SubmitFileSample` / `SubmitUrlSample` remain the simpler choice when a playbook run may stay open until the analysis finishes (up to the `timeout`, 30 minutes by default).

### `BuildReport` - Build Report

The heavy lifting. Takes `sample_ids` or `submission_ids` (from `SubmitFileSample`, each resolved to its sample); `sample_ids` wins when both are given. Per sample it fetches, one call after another: the analyses of the latest submission, VTIs, MITRE ATT&CK techniques, IOCs, classifications and threat names - then the screenshots of each analysis. Child samples, down to `max_recursion_depth`, get only their sample object and their IOCs: the comment shows each child as one row of the child tree, and `ExtractIocs` reads their IOCs; their other sections are used nowhere, so they are not fetched.

| Argument | Default | Notes |
|---|---|---|
| `sample_ids` / `submission_ids` | one required | |
| `max_recursion_depth` | `10` | maximum depth of child samples analyzed in the report, at most 10; `0` disables recursion |
| `include_screenshots` | `true` | include the screenshots of the submitted files - the top-level samples only, never their child samples |
| `ioc_severity_filter` | empty | list of `malicious` / `suspicious`: exactly one filters server-side; empty or both fetch both severities |
| `analysis_verdict_filter` | empty | list of `malicious` / `suspicious` / `clean` to include; empty includes all analyses, even those with an unknown verdict (adding all three does not) |

`include_screenshots` covers the top-level samples only: child samples' screenshots would multiply the comments for little value. In both filters, a value outside the allowed ones is ignored when a valid one is also given; a filter with no valid value (e.g. the typo `malicous`) fails the action, as in `ExtractIocs`.

Screenshots are read from each analysis archive (`logs/summary.json`), scaled to at most 800 px wide and re-encoded as JPEG, then embedded as base64 - Sekoia has no attachment API, so this is the only way they reach the alert. Every screenshot is kept; one that cannot be fetched or read (and a screenshot list that cannot be read) is named in the sample's "Partial data" note. An analysis without a screenshot list, such as a static analysis, simply has none.

A failing section lands in that sample's `errors` and every other section is still filled; a sample or submission that cannot be fetched at all lands in the report's `errors`.

**Results:** `report_path` (give it to `RenderReport` and `ExtractIocs`), `sample_ids`, `errors`.

### `RenderReport` - Render Report

Turns a report into the alert comment, laid out like VMRay's own report.

| Argument | Default | Notes |
|---|---|---|
| `report_path` (or `report`) | required | Build Report's `report_path` |
| `max_comment_kb` | `512` | maximum size of each screenshot comment |

**Results:**

- `content` — the main comment, for Comment Alert. Per sample, each section is a collapsible block, open by default, whose heading is the toggle:

  | Section | Contents |
  |---|---|
  | Overview | verdict, reason, filename, type, created, MD5/SHA1/SHA256, link to the VMRay report |
  | Detections | threat names and classifications |
  | IOC Summary | count per IOC type |
  | VMRay Threat Identifiers | VTIs, strongest first, with a coloured 1–5 score |
  | MITRE ATT&CK | technique links, plus a collapsed Details table (technique, tactics) |
  | Indicators of Compromise | every IOC with its type and verdict |
  | Analyses | each VM run, newest first, with its verdict |
  | Screenshots | how many screenshots were posted in the screenshot comments |
  | Child Samples | a collapsible tree: one row per child sample (verdict, name, type, children, link), children indented under their parent |

  Every table shows all its rows. When several samples are reported, each starts with "Sample i of N". Anything that failed to load (a section, a child sample, a screenshot) is listed with its reason in a "Partial data" note. When every requested sample failed, the comment says "No report could be built" and lists each sample with its reason, instead of "No matches found".

- `screenshot_comments` — the screenshots, grouped per analysis, each behind its own toggle that opens the image at the comment's full width. Split into as many comments as needed, each at most `max_comment_kb` and titled "VMRay Screenshots (i/N)"; post them with a Foreach. Sekoia rejects a playbook action argument above an undocumented size (SYM216), and Comment Alert only takes inline text, so one comment cannot hold them all.

Every value that comes from the analysed sample (filenames, URLs, IOC values, rule text) is escaped, so a crafted sample cannot inject links, remote images or markup into the comment.

### `ExtractIocs` — Extract IOCs

Extracts a report's IOCs as indicators for Sekoia's "Add IOC to IOC Collection" action.

| Argument | Default | Notes |
|---|---|---|
| `report_path` (or `report`) | required | Build Report's `report_path` |
| `ioc_severity_filter` | empty | IOC severities to extract: `malicious`, `suspicious`. Each IOC is judged on its own severity; a child sample's own SHA256 on its verdict. Empty (the default) = every IOC and every child sample's SHA256, whatever the severity or verdict; a value outside the allowed ones is ignored next to a valid one, and a filter with no valid value fails the action |
| `include_child_iocs` | `true` | also extract the child samples' IOCs and each child sample's own SHA256; `false` = root sample only |

**Results:** `indicators` (`[{value, type}]`, deduplicated) and `indicator_groups` - the same values grouped by type, one entry per non-empty type (`[{type, indicators}]`). "Add IOC to IOC Collection" takes one `indicator_type` per call, so a Foreach over `indicator_groups` pushes every type with one node.

| VMRay IOC | Pushed as |
|---|---|
| IPs | `IP address` |
| domains | `domain` |
| URLs | `url` |
| emails, email addresses | `email` |
| files | `hash` — the strongest of `sha256_hash`, `sha1_hash`, `md5_hash` per file |
| processes, mutexes, registry keys, filenames | not pushed - Sekoia's IOC collection has no matching type. They still appear in the comment |


## Playbook templates

| Template | Trigger | Use |
|---|---|---|
| `vmray1_sentinelone_manual_tmp.json` | Manual - an analyst runs it on an alert | Same steps as the Alert Created one, for testing: run it on an alert whose first event carries a SentinelOne threat ID |
| `vmray1_sentinelone_demo.json` | Alert Created | Fetches a SentinelOne threat's file from the endpoint and scans it |

Both work the same way. SentinelOne fetches the file, `StartFileSubmission` starts the analysis and returns at once, and the playbook then checks it with `Wait` + `CheckSubmissionStatus` after 2, 6 and 14 minutes (120 s, then 240 s, then 480 s), so no run stays open for the whole analysis. `completed` goes on to `BuildReport` → `RenderReport` → Comment Alert, then the screenshot comments and the IOC push. A `Get Child Samples` branch (suspicious or worse, up to 10 levels) also posts a comment listing the dangerous files VMRay found inside the submitted file. When VMRay refuses the file, finishes with an error, or is still analysing at the third check, a comment says so with the submission IDs. Each Foreach (screenshot comments, IOC types) sits behind a condition that skips it when its list is empty - Sekoia rejects a Foreach over an empty list ("Foreach input is not a list").

**After creating a playbook from a template:** select your VMRay1 account on the VMRay1 nodes, and set `ioc_collection_id` on "Add IOCs to IOC Collection". For the SentinelOne one, also select your SentinelOne account (its API user needs the permission to fetch threat files, and the endpoint's agent must be online) and consider limiting the trigger to SentinelOne rules: every file submitted consumes quota.

## Known limitations

**Comments are styled with HTML Sekoia allows, not CSS.** Sekoia renders comments as GitHub-flavoured markdown and strips `style` attributes and `<style>` blocks. Colours use `<font color>`, collapsible sections use `<details>`, and tables are HTML so short columns can be kept from wrapping (`nowrap`).

**Screenshots are embedded, not attached.** Sekoia has no alert or case attachment API, so screenshots are compressed and embedded as base64 images in their own comments. A sample with many screenshots posts many comments.

**No nested loops inside a loop.** A Foreach inside another Foreach cannot iterate a list produced inside the outer loop — its input arrives empty.

**Files come from another action, not from the alert.** Sekoia alerts don't carry sample bytes: `SubmitFileSample` submits files that an EDR action wrote to the playbook run's storage. Without one, a hash is looked up and a URL is detonated.

## Development

```
uv sync
mise run lint     # ruff check, ruff format --check, mypy
mise run test     # pytest — fast suite only
mise run format   # ruff fix + format
```

Action manifests (`action_*.json`) and `main.py` are generated from the code:

```
uv run sekoia-automation generate-files-from-code .
```

The generator reorders `main.py`'s imports; revert that file if nothing else in it changed. It also writes the action manifests without their `slug` (the action name in snake_case, e.g. `build_report`): put it back after `name` — a test fails until it is.

Every release adds a dated entry to `CHANGELOG.md` and bumps the version in `manifest.json`, `pyproject.toml` and the project's entry in `uv.lock`.

Three tests are marked `slow` (`pytest -m slow`, ~35s) — they exercise the retry adapter over a real local socket, not `requests_mock`. That's deliberate: `requests_mock` patches the transport at a level that bypasses any `HTTPAdapter` mounted on the session, so it cannot verify retry or `Retry-After` behaviour at all. Run the slow suite before any change to `client.py`'s retry configuration.
