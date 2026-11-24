# Test

Helpers for testing Sekoia.io playbooks. One action so far: **Download File**, which saves a file from a URL (for
example a zip) in the playbook run's storage, in the same format SentinelOne's "Get malwares from threat" uses. It
exists so the VMRay1 actions can be tried on any file, without an EDR.

## Configuration

None: the integration connects to nothing, so no account is needed. See [CONFIGURE.md](CONFIGURE.md).

## Actions

### `DownloadFile` - Download File

Downloads one file over HTTP(S) and writes it to the playbook run's storage as `download-<8 random hex>-<name>`, so two
downloads of one run never overwrite each other.

| Argument | Default | Notes |
|---|---|---|
| `url` | required | `http://` or `https://`, public addresses only |
| `file_name` | empty | the name to save under; empty means the name the server gives it (`Content-Disposition`), else the last part of the URL, else `download`. Only letters, digits and `._-` are kept |
| `max_size_mb` | `50` | 1 to 500. A larger file is dropped and the action fails |
| `timeout` | `120` | seconds the whole download may take, up to 1800 |
| `verify_ssl` | `true` | turn off only for a test server with a self-signed certificate |

**Results:** `files` (`[{"path": ...}]`, the shape Submit Sample takes as is), `file_name`, `size`, `sha256`,
`content_type`, `url` (the address the file came from, after redirects). No branches: a failure (HTTP error, too large,
empty, cut off, refused address) fails the action with the reason.

**What is refused.** The URL comes from a playbook, so the runtime must not be made to fetch internal addresses:
- only `http` and `https`;
- the host must resolve only to public addresses, so `localhost`, private ranges (`10.x`, `192.168.x`, ...) and the
  cloud metadata address `169.254.169.254` are refused;
- every redirect (at most 5) is checked the same way, before it is followed;
- the body is read in chunks and dropped as soon as it passes `max_size_mb`.

The address is resolved once to check it and again when the connection is made, so a server that answers differently
the second time (DNS rebinding) is not stopped. It is a test tool: do not point it at servers you do not trust.

## Using it with VMRay1

```
Download File ──► Submit Sample ──► Get Submission Result ──► Build Report ──► Get Sample ... actions
   files            files              submission_ids            sample_ids
```

| From | Field | To | Input | Expression |
|---|---|---|---|---|
| Download File | `files` | VMRay1 Submit Sample | `files` | `{{ node.N['files'] }}` |
| Submit Sample | `submission_ids` | VMRay1 Get Submission Result | `submission_ids` | `{{ node.N['submission_ids'] }}` |

Good files to try: the EICAR test file `https://secure.eicar.org/eicar.com.txt`, and the EICAR zip
`https://secure.eicar.org/eicar_com.zip`, which VMRay opens to find a child sample (that exercises Get Child Samples,
Get Child Sample Report and the child rows of the report). Every file submitted to VMRay consumes quota.

## Development

```
uv sync
uv run pytest tests/
uv run ruff check . && uv run ruff format --check . && uv run mypy .
```

The action manifest (`action_download_file.json`) is generated from the code, as in VMRay1; a test fails when it no
longer matches the models. Code is in `download_modules/` (`download_helpers.py` does the download and the checks,
`download_file_action.py` is the action, `download_models.py` its inputs and results).
