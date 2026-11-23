# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
