# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-11-24 - 1.5.0

### Changed
- Get Submission Result waits up to 60 minutes by default (`timeout` 3600 s, was 30 minutes) and asks VMRay at growing intervals: at once, then after 10, 20 and 30 seconds, then every 60 seconds. A quick analysis is noticed in seconds and a slow one is not asked about all the time. The `poll_interval` input is removed
- Get Submission Result has two branches: `completed`, and `failed` when a submission failed or the wait timed out (`timed_out` is then true). The `pending` branch and the single look (`timeout` 0) are gone: with a waiting action they only confused the playbook. `timeout` must be above 0
- The playbook templates drop the `pending` link and wait up to 60 minutes
- The Docker image is built on `python:3.14-slim-bookworm` instead of the full Debian image, and installs only the runtime dependencies (the lint tools were being installed too), so it is smaller and starts faster

## 2026-11-24 - 1.4.0

### Changed
- Get Submission Result now waits: it polls VMRay every `poll_interval` seconds (10 by default) until every submission has finished or `timeout` runs out (1800 s by default), then returns. `pending` now means the wait timed out, and the results gain `timed_out`. `timeout` 0 keeps the old single look. A playbook has no loop, so the Wait + Get Submission Result chain of three checks is replaced by one Get Submission Result block after the submit
- The playbook templates use that one block: Submit, Get Submission Result, Build Report. They are laid out top to bottom, with every arrow running downward
- Get Submission Result fails after three rounds in a row in which no submission could be checked, instead of staying pending until the timeout
- Fixed the child-samples comment of the Scan URL playbook ("found found while analysing")

## 2026-11-24 - 1.3.0

### Removed
- Submit Sample And Wait and Submit URL And Wait actions: no action waits for an analysis any more. Use Submit Sample or Submit URL, then a Sekoia `Wait` and Get Submission Result, as the playbook templates already do. Playbooks that used the removed actions must be changed, and the integration installed fresh (delete it in Sekoia and import it again)

### Changed
- One naming scheme for the code: `models.py` is now `module_models.py` (the module configuration) and the Build Report and indicator models moved to `report_models.py`; `submit_helpers.py` is now `submission_helpers.py`; the client methods are `submit_url`, `submit_sample` and `get_submission`; the tests have one file per action. The README has a Naming section. No behaviour change

## 2026-11-23 - 1.2.0

### Added
- Get Sample IOCs, Get Sample Mitre Attack Techniques, Get Sample VTIs, Get Sample Screenshots, Get Sample Report and Get Analysis Archive actions: read one part of a sample's analysis without building the whole report; the screenshots, report and archive are saved as files in the playbook run's storage

### Changed
- The inputs of the submit actions now start with the sample (the files or the URL), then Re-analyze and Tags, then the VMRay options; every input has a title, and the descriptions use the current action names
- Renamed the actions added in 1.1.0: Start File Submission is now Submit Sample, Start URL Submission is now Submit URL, and Check Submission Status is now Get Submission Result
- Renamed the actions that wait for the analysis to finish, so they do not clash: Submit File Sample is now Submit Sample And Wait, and Submit URL Sample is now Submit URL And Wait. Their IDs and behaviour are unchanged. Their technical names (`SubmitSampleAndWait`, `SubmitUrlAndWait`) changed too, so install this release fresh: delete the integration in Sekoia and import it again
- The models are split by area (`submission_models.py`, `sample_models.py`) and the shared sample lookups moved to `sample_helpers.py`; no behaviour change

## 2026-11-23 - 1.1.0

### Added
- Start File Submission and Start URL Submission actions: submit like Submit File Sample and Submit URL Sample but return at once with the submission IDs, without waiting for the analysis
- SentinelOne playbooks: Start File Submission, then Wait and Check Submission Status (after 2, 6 and 14 minutes) instead of one long-running Submit File Sample, plus a Get Child Samples comment listing the suspicious or malicious files found inside the submitted file
- Check Submission Status action: check once whether submissions have finished, with `completed` / `pending` / `failed` branches, for submissions started by any submit action
- Get Child Samples action: list the child samples VMRay found inside a sample, with parent, depth, hashes, verdict, VTI score and link; `max_depth` and `min_verdict` options and a `has_children` / `no_children` branch
- Get Sample Relations action: list the relation records VMRay keeps for a sample or a submission
- Get Child Sample Report action: build the full report of one child sample, checked to belong to its parent

## 2026-11-17 - 1.0.1

### Added
- version bamup

## 2026-11-17 - 1.0.0

### Added

- Initial release of VMRay1, a standalone copy of the VMRay module that installs next to it, focused on scanning files
- Get Samples By Hash action: look up SHA256, SHA1 or MD5 hashes in VMRay's existing analyses, at no quota cost
- Submit URL Sample action: submit a URL to VMRay and wait until every resulting submission has finished, with a timeout
- Submit File Sample action: submit files from the playbook run's storage (e.g. malware SentinelOne's Get malwares from threat fetched from an endpoint) to VMRay and wait until their analyses finish, with a timeout
- Build Report action: build the full VMRay report for sample IDs or submission IDs, including child samples and screenshots
- Render Report action: render a report as an alert comment, with screenshots split across extra comments under a size limit
- Extract IOCs action: extract a report's IOCs as typed indicators for an IOC collection, grouped by type
