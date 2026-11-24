## Configuration

Download a file from a URL into the playbook run's storage, to feed other integrations (for example VMRay1's Submit
Sample) in tests. The integration connects to nothing and has no settings.

### In Sekoia.io: Add the integration

1. Open `Integrations` from the sidebar, then `New integration`, and add a custom integration from the Git repository
   that holds it: the folder is `Test`.
2. Open the `Test` integration. It needs no account: select none on its action nodes.

### In Sekoia.io: Use it in a playbook

3. Add `Download File` and set `url`, for example `https://secure.eicar.org/eicar_com.zip` (a zip with one test file
   inside).
4. Give its `files` to VMRay1's `Submit Sample`: `{{ node.N['files'] }}`, where `N` is the Download File node.
