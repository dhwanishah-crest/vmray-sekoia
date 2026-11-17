# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-11-17 - 1.0.0

### Added

- Initial release of VMRay1, a standalone copy of the VMRay module that installs next to it, focused on scanning files
- Download File action: download a file from an http(s) URL into the playbook run's storage, public hosts only, with a size limit
- Submit File Sample action: submit files from the playbook run's storage (e.g. malware SentinelOne's Get malwares from threat fetched from an endpoint, or a Download File result) to VMRay and wait until their analyses finish, with a timeout
- Build Report action: build the full VMRay report for sample IDs or submission IDs, including child samples and screenshots
- Render Report action: render a report as an alert comment, with screenshots split across extra comments under a size limit
- Extract IOCs action: extract a report's IOCs as typed indicators for an IOC collection, grouped by type
