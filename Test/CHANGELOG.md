# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-11-24 - 1.0.0

### Added
- A nested sample archive (`samples/nested_multi_child.zip`, built by `samples/build_nested_archive.py`) with ten harmless files in three zip levels, to test Get Child Samples and the child tree of the VMRay1 report
- Tests with real zip data: byte-exact saving, the nested archive after the download, and a check that the committed archive is what the builder makes
- Download File action: download a file (for example a zip) from a public http(s) URL into the playbook run's storage, in the `files` format of SentinelOne's Get malwares from threat, with a size limit, a time limit and checks on the address and on every redirect
