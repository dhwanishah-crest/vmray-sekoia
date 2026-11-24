# VMRay1

VMRay Platform - Agentless hypervisor-based sandbox for malware detonation, VTI scoring and IOC extraction.

VMRay1 sends files and URLs to VMRay and brings the results back into Sekoia.io playbooks: submit a file (fetched from an EDR such as SentinelOne) or a URL, follow the analysis, read any part of the result (IOCs, MITRE ATT&CK techniques, threat identifiers, screenshots, VMRay's own report, the files found inside the sample), or build the full report and post it on the alert as a comment with screenshots, and push the indicators found to a Sekoia IOC collection. It installs next to the original VMRay integration and does not replace it.

## Configuration

See [CONFIGURE.md](CONFIGURE.md): requirements, creating the VMRay API key, connecting the account in Sekoia.io and a typical playbook chain.

## How it works

```
file (EDR) ──► Submit Sample ─┐
URL ─────────► Submit URL ────┤                                  ┌─► Get Sample IOCs / VTIs / Mitre ATT&CK techniques
                              ├─► Get Submission Result ─► sample ┼─► Get Sample Screenshots / Report, Get Analysis Archive
                              │        (completed)                ├─► Get Child Samples ─► Get Child Sample Report
  (waits for the analysis)    │                                   └─► Build Report ─► Render Report ─► alert comment
hashes ──► Get Samples By Hash ──────────────────────────────────────────────────────► Extract IOCs ─► IOC collection
```

1. **Get something to analyse.** An EDR action such as SentinelOne's "Get malwares from threat" saves a file on the playbook run's storage and returns `files`, a list of `{"path": ...}`. Or use a URL, or look hashes up with `Get Samples By Hash` (no quota).
2. **Submit it.** `Submit Sample` / `Submit URL` start the analysis and return at once with the submission IDs. Submitting consumes quota.
3. **Follow it.** `Get Submission Result` waits until the submissions have finished and returns them (`completed`, or `failed` when one failed or the wait timed out). One block covers the whole wait, because a playbook has no loop.
4. **Read the result.** Take only what you need with the `Get Sample ...` actions, look inside the sample with `Get Child Samples` and `Get Sample Relations`, or have `Build Report` gather everything into one JSON file on the run's storage. Only the file's path travels between nodes: a report with screenshots is far larger than Sekoia accepts as an action argument (SYM216).
5. **Use the report.** `Render Report` turns it into the alert comment; `Extract IOCs` turns it into indicators for an IOC collection. Neither calls VMRay or Sekoia.

## Actions

### At a glance

| Group | Action | What it does | Branches | Quota |
|---|---|---|---|---|
| Submit and follow | Submit Sample | uploads files and returns at once | `submitted` / `submission_failed` | yes |
| | Submit URL | submits a URL and returns at once | `submitted` / `submission_failed` | yes |
| | Get Submission Result | waits until submissions have finished | `completed` / `failed` | no |
| Look up | Get Samples By Hash | finds the samples VMRay already knows for hashes | `found` / `not_found` | no |
| Read one part of a sample | Get Sample IOCs | the IOCs by category | `found` / `not_found` | no |
| | Get Sample Mitre Attack Techniques | the ATT&CK techniques | `found` / `not_found` | no |
| | Get Sample VTIs | the VMRay Threat Identifiers | `found` / `not_found` | no |
| | Get Sample Screenshots | saves the screenshots as files | `found` / `not_found` | no |
| | Get Sample Report | saves VMRay's own report as a file | - | no |
| | Get Analysis Archive | saves an analysis archive (or one file of it) | - | no |
| Child samples | Get Child Samples | lists the files found inside a sample | `has_children` / `no_children` | no |
| | Get Sample Relations | the relation records of a sample or submission | `found` / `not_found` | no |
| | Get Child Sample Report | the full report of one child | - | no |
| The alert report | Build Report | gathers everything into one report file | - | no |
| | Render Report | turns the report into the alert comment | - | no |
| | Extract IOCs | turns the report into typed indicators | - | no |

An action with no branch column entry has a single exit. Names in the playbook editor are the ones above; the names in
backticks in the sections below are the action's technical name.

### Chaining actions in a playbook

Sekoia keeps each node's result and a later node reads fields of it. These are the hand-offs the actions are built
for (`N` is the node that produced the field):

| From | Field | To | Input | Expression |
|---|---|---|---|---|
| Submit Sample / Submit URL | `submission_ids` | Get Submission Result | `submission_ids` | `{{ node.N['submission_ids'] }}` |
| SentinelOne Get malwares from threat, or any action that saves files | `files` | Submit Sample | `files` | `{{ node.N['files'] }}` |
| Get Submission Result, Get Samples By Hash | `sample_ids` | any Get Sample action, Get Child Samples | `sample_id` | `{{ node.N['sample_ids'][0] }}` |
| the same | `submission_ids` | any Get Sample action, Get Child Samples | `submission_id` | `{{ node.N['submission_ids'][0] }}` |
| the same | `submission_ids` or `sample_ids` | Build Report | `submission_ids` or `sample_ids` | `{{ node.N['submission_ids'] }}` |
| Build Report, Get Child Sample Report | `report_path` | Render Report, Extract IOCs | `report_path` | `{{ node.N['report_path'] }}` |
| Extract IOCs | `indicator_groups` | Foreach, then Add IOC to IOC Collection | per group | `{{ node.F.default.value['indicators'] }}` |
| Get Child Samples | `sample_ids` | Foreach, then Get Child Sample Report | `child_sample_id` | `{{ node.F.default.value }}` |
| Get Child Samples | `sample_id` | Get Child Sample Report | `parent_sample_id` | `{{ node.N['sample_id'] }}` |
| Get Sample Screenshots | `screenshots[].analysis_id` | Get Analysis Archive | `analysis_id` | `{{ node.N['screenshots'][0]['analysis_id'] }}` |
| Get Sample Screenshots, Get Sample Report, Get Analysis Archive | `files` | any action that takes files | `files` | `{{ node.N['files'] }}` |

Use the branches rather than testing fields: `has_children` and `found` are there so a playbook can skip the steps that
follow (Sekoia rejects a Foreach over an empty list).

**Get Submission Result does the waiting.** An analysis takes minutes, and a Sekoia playbook has no loop (it has
Foreach over a list, but nothing that repeats a step until something is true, and no way back to an earlier node). So
the wait lives in one action: `Submit Sample` / `Submit URL` → `Get Submission Result` (polls VMRay every
growing intervals, up to `timeout`) → `Build Report`. Nothing else is needed between them.

### `SubmitSample` - Submit Sample

Uploads files from the playbook run's storage (`POST /sample/submit` with `sample_file`) and **returns at once** with the submission IDs. Built for SentinelOne's "Get malwares from threat", which fetches a threat's file(s) from the endpoint, decrypts them and writes them to the storage named by SHA-1. Consumes quota.

| Argument | Default | Notes |
|---|---|---|
| `files` | required | paths in the playbook run's storage. Takes another action's output as is: a list of `{"path": ...}` objects or of paths, or a single one. Duplicates are submitted once |
| `reanalyze` | `true` | re-analyze known samples on submission |
| `tags` | `["sekoia"]` | tags to attach to the sample |
| `shareable` | `false` | share the sample's hash with VirusTotal |
| `max_recursive_samples` | `10` | maximum amount of recursive samples analyzed, at most 10; `0` disables recursion |
| `analyzer_mode`, `max_jobs`, `enable_reputation`, `enable_whois`, `known_malicious`, `known_benign`, `analysis_timeout`, `net_scheme_name` | empty | VMRay submission options; empty ones are not sent, so the VMRay user's analyzer settings apply |

Each file is submitted on its own and sent under its storage-path name; VMRay detects its type from the content. A path outside the storage (absolute, or with `..`), a missing or empty file, and a file VMRay refuses are listed in `errors` with their `file`, and the other files still go through. No archive settings: the files arrive already extracted.

**Outputs:** `submitted` (VMRay started at least one submission) / `submission_failed`. **Results:** `submitted` (bool), `submission_ids` (started, not finished: input for `GetSubmissionResult`), `submitted_files`, `errors`.

### `SubmitUrl` - Submit URL

Submits a URL (`POST /sample/submit` with `sample_url`) and **returns at once** with the submission IDs. Consumes quota.

It takes the same inputs as `SubmitSample`, with `sample_url` (required: the URL to detonate) in place of `files`. There are no archive settings (archive password, compound sample): they only apply to submitted files. `analysis_timeout` is how long VMRay analyses.

**Outputs:** `submitted` / `submission_failed`. **Results:** `submitted` (bool), `submission_ids`, `errors` (VMRay's reasons for a rejected submission).

### `GetSubmissionResult` - Get Submission Result

Waits until submissions have finished, then returns them. It makes a `GET /submission/{id}` for each submission still running, until none is pending or `timeout` runs out. It asks at once, then after waiting 10, 20 and 30 seconds, then every 60 seconds, so a quick analysis is noticed quickly and a slow one is not asked about all the time. A submission that has finished is not asked about again. Takes the `submission_ids` of `SubmitSample` or `SubmitUrl`. Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `submission_ids` | required | one ID or a list; duplicates are checked once |
| `timeout` | `3600` | seconds to wait for every submission to finish; then the `failed` branch with `timed_out` true |

**Outputs:**
- `completed`: every submission has finished and at least one finished without error. `submission_ids` and `sample_ids` are ready for `BuildReport`.
- `failed`: nothing to build a report from: every submission finished with an error, or the wait timed out with a submission still running (`timed_out` is true and `pending_submission_ids` lists it). The submissions that did finish are in the results either way.

**Results:** `all_finished`, `timed_out`, `submissions`, `submission_ids` and `sample_ids` (finished without error), `pending_submission_ids`, `failed_submission_ids`, `errors`.

A submission that cannot be checked is not called failed on the first try, because the next check may work; if it is still unreachable when the wait ends, `errors` says why. When not one submission could be checked in three rounds in a row (a wrong API key, VMRay down) the action raises an error, so a playbook never reads "timed out" when nothing was looked at.

**In a playbook** it is one block between the submit and the report: `Submit URL` (`submitted`) → `Get Submission Result` → `completed` goes on to `Build Report`; `failed` goes to a comment that the analysis did not finish. The run stays open while the action waits, up to `timeout` (60 minutes by default).

### `GetSamplesByHash` - Get Samples By Hash

Looks up SHA256, SHA1 or MD5 hashes in VMRay's existing analyses and returns every matching sample. Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `hashes` (File hashes) | required | list of SHA256, SHA1 or MD5 hashes to look up; duplicates ignored, no quota used |

**Outputs:** `found` (at least one sample) / `not_found` (none). **Results:** `sample_ids`, `samples`, `not_found` (hashes VMRay has never analysed), `errors` (per hash: invalid value or lookup failure).

### `GetSampleIocs` - Get Sample IOCs

The indicators of compromise VMRay found for a sample (`GET /rest/sample/{id}/iocs`), by category (URLs, domains, IPs, files, mutexes, ...). Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `sample_id` (Sample ID) | | the sample, e.g. `sample_ids` of Get Submission Result |
| `submission_id` (Submission ID) | | resolved to its sample; used when `sample_id` is empty. One of the two is required |
| `ioc_severity_filter` | empty | `malicious` and/or `suspicious`; exactly one is asked of VMRay, none or both fetch both. A list with no valid value is an error |

**Outputs:** `found` (at least one IOC) / `not_found`. **Results:** `iocs` (as VMRay returns them, by category), `ioc_counts`, `ioc_count`, `sample_id`. To push IOCs to an IOC collection use `ExtractIocs`, which takes a `BuildReport` result.

### `GetSampleMitreAttackTechniques` - Get Sample Mitre Attack Techniques

The MITRE ATT&CK techniques VMRay saw a sample use (`GET /rest/sample/{id}/mitre_attack`). Costs no quota. Takes `sample_id` or `submission_id`, like Get Sample IOCs.

**Outputs:** `found` / `not_found`. **Results:** `techniques` (as VMRay returns them), `technique_count`, `technique_ids` (the `technique_id` or `id` of each technique, once each), `sample_id`.

### `GetSampleVtis` - Get Sample VTIs

The VMRay Threat Identifiers of a sample (`GET /rest/sample/{id}/vtis`). Costs no quota. Takes `sample_id` or `submission_id`, plus:

| Argument | Default | Notes |
|---|---|---|
| `min_score` (Minimum score) | `0` | keep only identifiers scored at least this, 0 to 5; `0` returns every identifier. An identifier without a numeric score never reaches a minimum |

**Outputs:** `found` / `not_found`. **Results:** `threat_indicators` (as VMRay returns them), `vti_count`, `max_score`, `sample_id`.

### `GetSampleScreenshots` - Get Sample Screenshots

Saves the screenshots VMRay took while analysing a sample as files on the playbook run's storage. It reads the analyses of the sample's latest submission, newest first, and each one's screenshot list in its analysis archive. Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `sample_id` / `submission_id` | | as above |
| `max_screenshots` (Max screenshots) | `20` | the most to save, 1 to 200; the newest analyses are read first |

**Outputs:** `found` (at least one saved) / `not_found`. **Results:** `files` (`[{"path": ...}]`, the shape the other file actions take), `screenshots` (each with `path`, `analysis_id`, `name`, `size`), `screenshot_count`, `errors`. The images are saved as VMRay has them and are not embedded in the result, which would be far larger than Sekoia accepts; `BuildReport` still embeds compressed ones for the alert comment. An analysis without a screenshot list (a static analysis) is not an error. A path in a screenshot list that is absolute or contains `..` is never requested and is named in `errors`.

### `GetSampleReport` - Get Sample Report

Downloads the report VMRay generated for a sample (`GET /rest/sample/{id}/report`) into the playbook run's storage. VMRay's API reference lists this endpoint but not what it answers with, so the answer is saved as received and its `content_type` is returned; the file extension follows it (`.pdf`, `.json`, `.zip`, `.html`, else `.bin`). Costs no quota. Takes `sample_id` or `submission_id`, plus `max_size_mb` (default `64`).

**Results:** `files` (`[{"path": ...}]`), `file_name`, `content_type`, `size`, `sha256`, `sample_id`. This is VMRay's own report; the report Sekoia comments on an alert is built by `BuildReport` and `RenderReport`.

### `GetAnalysisArchive` - Get Analysis Archive

Downloads an analysis archive from VMRay (`GET /rest/analysis/{id}/archive`), or one file of it (`.../archive/{path}`), into the playbook run's storage. Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `analysis_id` (Analysis ID) | required | e.g. an `analysis_id` from `BuildReport`'s report or from Get Sample Screenshots |
| `archive_path` (Archive path) | empty | one file such as `logs/summary.json`; empty downloads the whole ZIP. A path that is absolute or contains `..` is an error |
| `max_size_mb` (Max size) | `64` | 1 to 512; a bigger answer fails the action instead of filling the storage |

**Results:** `files` (`[{"path": ...}]`), `file_name`, `size`, `sha256`.

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

### `BuildReport` - Build Report

The heavy lifting. Takes `sample_ids` or `submission_ids` (from `GetSubmissionResult`, each resolved to its sample); `sample_ids` wins when both are given. Per sample it fetches, one call after another: the analyses of the latest submission, VTIs, MITRE ATT&CK techniques, IOCs, classifications and threat names - then the screenshots of each analysis. Child samples, down to `max_recursion_depth`, get only their sample object and their IOCs: the comment shows each child as one row of the child tree, and `ExtractIocs` reads their IOCs; their other sections are used nowhere, so they are not fetched.

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
| `vmray1_scan_url.json` | Manual - an analyst runs it on an alert | Scans a URL (the EICAR test file by default; set your own on "VMRay: Submit URL"). Needs no EDR |
| `vmray1_sentinelone_demo.json` | Alert Created | Fetches a SentinelOne threat's file from the endpoint and scans it |
| `vmray1_sentinelone_manual_tmp.json` | Manual - an analyst runs it on an alert | Same steps as the Alert Created one, for testing: run it on an alert whose first event carries a SentinelOne threat ID |

All three work the same way after the file or URL is submitted: `Submit Sample` / `Submit URL` start the analysis and return at once, and one `Get Submission Result` waits for it (up to 60 minutes). `completed` goes on to `Build Report` → `Render Report` → Comment Alert, then the screenshot comments and the IOC push. A `Get Child Samples` branch (suspicious or worse, up to 10 levels) also posts a comment listing the dangerous files VMRay found inside the submitted file. When VMRay refuses the submission, finishes with an error, or is still analysing when the wait ends, a comment says so with the submission IDs. Each Foreach (screenshot comments, IOC types) sits behind a condition that skips it when its list is empty - Sekoia rejects a Foreach over an empty list ("Foreach input is not a list").

**After creating a playbook from a template:** select your VMRay1 account on the VMRay1 nodes, and set `ioc_collection_id` on "Add IOCs to IOC Collection". For the SentinelOne ones, also select your SentinelOne account (its API user needs the permission to fetch threat files, and the endpoint's agent must be online) and consider limiting the trigger to SentinelOne rules: every file or URL submitted consumes quota.

## Known limitations

**Comments are styled with HTML Sekoia allows, not CSS.** Sekoia renders comments as GitHub-flavoured markdown and strips `style` attributes and `<style>` blocks. Colours use `<font color>`, collapsible sections use `<details>`, and tables are HTML so short columns can be kept from wrapping (`nowrap`).

**Screenshots are embedded, not attached.** Sekoia has no alert or case attachment API, so screenshots are compressed and embedded as base64 images in their own comments. A sample with many screenshots posts many comments.

**No nested loops inside a loop.** A Foreach inside another Foreach cannot iterate a list produced inside the outer loop — its input arrives empty.

**Files come from another action, not from the alert.** Sekoia alerts don't carry sample bytes: `SubmitSample` submits files that an EDR action wrote to the playbook run's storage. Without one, a hash is looked up and a URL is detonated.

## Development

```
uv sync
mise run lint     # ruff check, ruff format --check, mypy
mise run test     # pytest — fast suite only
mise run format   # ruff fix + format
```

### Naming

One name runs through an action, from its display name to its files:

| Piece | Rule | Example (Get Sample VTIs) |
|---|---|---|
| Display name | `Verb Noun`, Title Case | Get Sample VTIs |
| Class and docker name | the display name without spaces | `GetSampleVtis` |
| Code | `vmray_modules/<snake_case>_action.py` | `get_sample_vtis_action.py` |
| Manifest | `action_<snake_case>.json` | `action_get_sample_vtis.json` |
| Models | `<Class>Arguments` and `<Class>Results`, in `<area>_models.py` | `GetSampleVtisArguments` |
| Client method | `verb_noun` of the VMRay resource, never an action name | `get_sample_threat_indicators` |

Shared code sits in `<area>_helpers.py` and `<area>_models.py` (`submission`, `sample`, `child`, `report`); `module_models.py` holds the module configuration. The same split applies to the VMRay words: a **submission** is one analysis job (`submission_id`, finished or not, with errors or not) and a **sample** is the file or URL it analysed (`sample_id`, with its report, IOCs and child samples). One sample can have several submissions, and a submission points at its sample with `submission_sample_id`. So the submit actions and `Get Submission Result` talk about submissions, every `Get Sample ...` action about samples, and an action that takes either accepts `sample_id` or `submission_id`.

Action manifests (`action_*.json`) and `main.py` are generated from the code:

```
uv run sekoia-automation generate-files-from-code .
```

The generator reorders `main.py`'s imports; revert that file if nothing else in it changed. It also writes the action manifests without their `slug` (the action name in snake_case, e.g. `build_report`): put it back after `name` — a test fails until it is.

Every release adds a dated entry to `CHANGELOG.md` and bumps the version in `manifest.json`, `pyproject.toml` and the project's entry in `uv.lock`.

Three tests are marked `slow` (`pytest -m slow`, ~35s) — they exercise the retry adapter over a real local socket, not `requests_mock`. That's deliberate: `requests_mock` patches the transport at a level that bypasses any `HTTPAdapter` mounted on the session, so it cannot verify retry or `Retry-After` behaviour at all. Run the slow suite before any change to `client.py`'s retry configuration.
