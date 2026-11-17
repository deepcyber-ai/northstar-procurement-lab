# Northstar Procurement 0.1.0-rc.2

**Release status:** Docker-only public-review candidate, prepared 17 November
2026. It is not a production application or an independent security certification.
Northstar Procurement is licensed under [Apache-2.0](../LICENSE); see
[NOTICE](../NOTICE) for attribution. External tools and dependencies retain
their own licences.

## Preview scope

The bundle contains the current local Docker Compose application: Angular frontend,
Spring backend and synthetic identity provider, Nginx gateway, separate owner-control
service, and network-isolated export worker. Runtime source, existing tests, OpenAPI,
local setup instructions, the discovery-to-retest tutorial, three Northstar
screenshots, and a reusable retest brief template are included.

There are 17 documented seeded exercises with Vulnerable, Fixed and Custom profiles.
The lab starts Vulnerable. Fixed disables the documented seeded defects; it does not
make this intentionally vulnerable teaching application production-ready. Use only
synthetic data and authorised, isolated targets. Keep the default loopback bindings.

Start with the [README](../README.md), [local tool connectivity](LOCAL_TESTING_SETUP.md),
and [lab operations](LAB_OPERATIONS.md). The [known-vulnerability catalogue](KNOWN_VULNERABILITIES.md)
contains assessment spoilers. Owner controls are separate from the assessment target.

## Distribution boundary

The candidate deliberately omits AWS/Terraform deployment machinery, private
operational runbooks, `.env` files, runtime databases, signing keys, credentials,
scan results, caches, dependency installs, build output and prior archives.
The root `.env.example` is the only environment file included.

One static asset remains at `infra-aws-native/functions/owner-demo.html` because
the local owner-control Dockerfile copies it. Its presence does **not** include
or support an AWS deployment workflow in this preview.

The public repository is a clean snapshot of this curated Docker-only ZIP; the
private development repository and its earlier Git history are not published.
GitHub's tag source archive and the attached ZIP therefore describe the same
source files, although their archive formats and root folders differ. Docker
builds still require normal base-image and dependency downloads. No container,
scanner, network tunnel, or deployment is started by packaging.

## Reproduce and inspect the candidate

Python 3 is needed for the local setup helpers and packaging. No additional Python
package is required for the release fixture tests:

```bash
python3 scripts/test_package_distribution.py
bash package_distribution.sh --check
bash package_distribution.sh
```

The first command uses synthetic fixtures in temporary directories. `--check`
audits the current source and a temporary ZIP without writing a deliverable.
Packaging creates this versioned folder only after the ZIP audit succeeds:

```text
dist/northstar-procurement-0.1.0-rc.2/
  northstar-procurement-0.1.0-rc.2.zip
  northstar-procurement-0.1.0-rc.2.zip.sha256
```

From that folder, run `shasum -a 256 -c northstar-procurement-0.1.0-rc.2.zip.sha256`
before unpacking. An existing candidate folder is never replaced; prepare another
candidate version for a changed snapshot. Failed builds do not erase earlier
deliverables. The checksum detects changes but is not a publisher signature.

## Validation limits

Release fixture tests cover required-file inclusion, data/credential exclusions,
unsafe path and link rejection, ZIP integrity, checksums and preservation of earlier
deliverables. Credential detection is heuristic and is not a guarantee that every
possible secret is detected. Review the exact candidate before sharing it publicly.

Earlier preparation recorded 64 passing backend tests. For this candidate,
14 owner-control tests passed, 13 export-worker tests passed (one skipped), the
frontend production build succeeded, and 16 release-package tests passed.
The local-connectivity fixture suite also runs offline. These checks
do not establish acceptance of a fresh extracted ZIP or a live deployed target.

Full ARTEX and Strix assessment/retest runs are intentionally deferred to the
operator, who chose to prepare the release without running those AI tools. No
paid-provider or local-model assessment call is part of this release preparation.
Packaging itself does not run application tests, Docker builds, scanners, or
end-to-end deployment acceptance. Existing application tests are included for
separately authorised validation; no new live-testing claim is made here.
