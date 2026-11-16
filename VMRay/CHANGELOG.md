# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-11-16 - 1.1.1

### Fixed

- Submit File Sample: the `files` input is now a plain array of strings, with no `anyOf` item type and no `minItems`, so the playbook editor stops flagging the node ("Account is invalid, fields are missing"). An empty list is still refused when the action runs

## 2026-11-12 - 1.1.0

### Added

- Submit File Sample action: submit files from the playbook run's storage (e.g. malware SentinelOne's Get malwares from threat fetched from an endpoint) to VMRay and wait until their analyses finish, with a timeout
- Playbook template "VMRay: Sandbox SentinelOne malware on alert creation" (`playbooks/templates/new.json`)

## 2026-10-16 - 1.0.0

### Added

- Initial release
- Get Samples By Hash action: look up SHA256/SHA1/MD5 hashes in VMRay's existing analyses (no quota used)
- Submit URL Sample action: submit a URL to VMRay and wait until its analyses finish, with a timeout
- Build Report action: build the full VMRay report for sample IDs or submission IDs — analyses, VMRay Threat Identifiers, MITRE ATT&CK, IOCs, classifications, threat names and screenshots, including child samples
- Render Report action: render a report as an alert comment, with screenshots split across extra comments under a size limit
- Extract IOCs action: extract a report's IOCs as typed indicators for an IOC collection, grouped by type
