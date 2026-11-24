## Configuration

Look up file hashes in VMRay, detonate URLs or scan files from a Sekoia.io playbook, post the full VMRay report on the alert as a comment (with screenshots), and push the indicators found to a Sekoia.io IOC collection.

### Requirements

- A VMRay Platform account, cloud (e.g. `https://eu.cloud.vmray.com`, `https://us.cloud.vmray.com`) or on-premises, running VMRay Platform **2026.2 or later**. On older versions, the recursive threat names and classifications of child samples are missing from the report.
- To detonate URLs or files (`Submit URL And Wait`, `Submit Sample And Wait`), a VMRay plan that allows submissions: VMRay rejects submissions on the DeepResponse plan. Looking up hashes works on every plan and consumes no quota; every URL or file detonation consumes quota.

### In VMRay: Create an API key

1. Sign in to the VMRay Platform with the user Sekoia.io will act as.
2. Open your user profile and go to the API keys section.
3. Create an API key and copy it. You will use it in the next steps.

### In Sekoia.io: Connect the VMRay integration

4. In Sekoia.io, open `Integrations` from the sidebar.
5. Search for `VMRay1` and select the VMRay1 integration from the results.
6. Click `Show accounts`, then `Connect an account`.
7. Fill in the `Add new account` form:

    - `Give a name to this account`: a label of your choice (e.g. `VMRay1`).
    - `Base URL`: the URL of your VMRay Platform, e.g. `https://eu.cloud.vmray.com`.
    - `Api Key`: the API key created in VMRay.
    - `Verify SSL`: keep it enabled. Disable it only for an on-premises appliance with a self-signed certificate.

    Click `Add account`.

### In Sekoia.io: Use the VMRay actions in a playbook

8. Open or create a playbook, add the VMRay1 actions, and select the VMRay1 account you just connected in each one's `Account` tab. A typical chain:

    - `Get Samples By Hash` (file hashes of the alert) or `Submit URL And Wait` (a URL of the alert), or
    - an EDR action such as SentinelOne's `Get malwares from threat`, which puts the file in the run's storage,
    - `Submit Sample And Wait` with their `files` (it waits for the analysis), or `Submit Sample` / `Submit URL`, which return at once: then a Sekoia `Wait` and `Get Submission Result` with the `submission_ids` they return,
    - optionally `Get Sample IOCs`, `Get Sample VTIs`, `Get Sample Mitre Attack Techniques`, `Get Sample Screenshots`, `Get Sample Report` or `Get Analysis Archive` to read one part of the analysis without building the whole report,
    - optionally `Get Child Samples` on the file's `sample_ids` to see what VMRay found inside it (a `has_children` branch skips the rest when there is nothing), and `Get Child Sample Report` for one chosen child,
    - then `Build Report` with the `sample_ids` or `submission_ids` they return,
    - then `Render Report` and the Sekoia.io `Comment Alert` action to post the report on the alert, with a `Foreach` over `screenshot_comments` for the screenshots,
    - and `Extract IOCs` with the Sekoia.io `Add IOC to IOC Collection` action to push the indicators, with a `Foreach` over `indicator_groups`.

Ready-made playbooks are in `playbooks/templates/`: "VMRay1: Scan URL" (run by an analyst, needs no EDR), "VMRay1: Alert Created - Scan SentinelOne file", which scans the file of a SentinelOne threat, and a Manual-trigger copy of it for testing. After creating a playbook from one, select your VMRay1 account on the VMRay1 nodes and set the IOC collection on `Add IOCs to IOC Collection`. Every file submitted consumes quota.
