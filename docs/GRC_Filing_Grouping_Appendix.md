# Appendix — Issue Grouping: names behind the counts

Generated 2026-09-17 15:49 UTC by `scripts/generate_grouping_appendix.py` from the
`security_portal` database. Every table here is produced by that script;
nothing in it is typed by hand.

**Companion documents:** `docs/GRC_Filing_Grouping_Status_Briefing.md`
(leadership) and `docs/GRC_Filing_Grouping_Status_Technical.md` (technical).

**What this appendix deliberately omits.** No code snippets, and no
secret values: for the scanners whose finding *is* a credential, the
matched line is withheld everywhere outside AuditGitHub itself. File
paths are included, because a path is what an owner acts on. Findings
already marked not-actionable are excluded from the fileable counts and
are not listed.

## Figures

| Measure | Value |
| --- | --- |
| Findings in the database | 767,974 |
| Findings carrying a scanner rule identifier | 767,974 |
| Findings already marked not-actionable | 546,977 |
| Findings whose recorded path is a temporary scan directory | 573,526 |
| Projects (repositories) known | 2,540 |
| Distinct scanners represented | 10 |
| Distinct defects (scanner + rule) across all severities | 2,638 |
| Distinct defects at Critical/High/Medium, actionable | 2,397 |
| Of those, defects touching more than 10 projects | 241 |
| Cross-scanner rule pairs worth checking (Critical/High/Medium) | 478 |
| Cross-scanner rule pairs worth checking (all severities) | 834 |
| Of those, still unchecked | 475 |
| Merge proposals recorded | 3 |
| Proposals waiting on a person | 3 |
| Waiting proposals that propose a merge | 0 |
| Approved merges (these group findings today) | 0 |
| Approved as separate | 0 |
| Rejected proposals | 0 |
| Largest group under the retired key, findings | 18,269 |
| Largest group under the retired key, distinct defects inside it | 480 |
| Largest group under the retired key, projects spanned | 137 |
| grype at exactly `/package-lock.json`: findings | 11,517 |
| grype at exactly `/package-lock.json`: distinct defects | 386 |
| grype at exactly `/package-lock.json`: projects | 110 |

## A. The retired grouping key, worst groups first

Grouping used to key on scanner plus file name. Each row is one group
under that key: `distinct defects inside it` is how many genuinely
different problems a single issue would have claimed to cover.

Rows are grouped by file *name*, so a project with lock files in three
directories contributes all three. The retired key compared the whole
recorded path, which is stricter: for grype at exactly
`/package-lock.json` it is 11,517 findings, 
386 distinct defects, 
110 projects. Both figures are of the same
problem; the first row below is the file-name view of it.

| Scanner | File name | Findings | Distinct defects inside | Projects |
| --- | --- | --- | --- | --- |
| grype | `package-lock.json` | 18,269 | 480 | 137 |
| trivy-fs | `package-lock.json` | 13,172 | 434 | 109 |
| whispers | `config` | 6,553 | 2 | 1,382 |
| whispers | `terraform.tfvars` | 6,318 | 1 | 24 |
| grype | `pom.xml` | 4,057 | 274 | 74 |
| whispers | `Kconfig` | 3,456 | 1 | 4 |
| whispers | `index.html` | 3,234 | 1 | 33 |
| trufflehog | `app-release.apk` | 2,615 | 3 | 1 |
| trivy-fs | `Dockerfile` | 2,575 | 12 | 205 |
| horusec | `libTestStudioExtension.a` | 2,568 | 1 | 1 |
| trivy-fs | `r-storage-account.tf` | 2,495 | 4 | 62 |
| grype | `go.mod` | 2,410 | 29 | 20 |
| grype | `requirements.txt` | 2,185 | 159 | 36 |
| whispers | `default.auto.tfvars.json` | 2,148 | 9 | 12 |
| trivy-fs | `main.tf` | 2,066 | 35 | 41 |
| mobsf:android | `strings.xml` | 1,970 | 2 | 4 |
| whispers | `.editorconfig` | 1,737 | 1 | 352 |
| whispers | `.env` | 1,672 | 7 | 96 |
| trivy-fs | `pom.xml` | 1,627 | 206 | 6 |
| trivy-fs | `app-template.yaml` | 1,442 | 18 | 8 |
| horusec | `break_js.js` | 1,260 | 1 | 1 |
| horusec | `DeviceInfoResponseMessages.java` | 920 | 2 | 1 |
| horusec | `combined_cacert.pem` | 864 | 1 | 1 |
| grype | `poetry.lock` | 820 | 89 | 13 |
| horusec | `CPM.js` | 816 | 4 | 1 |
| horusec | `page.tsx` | 740 | 2 | 12 |
| mobsf:android | `detekt-baseline-app.xml` | 725 | 1 | 1 |
| horusec | `DeviceInfoRequestMessages.java` | 715 | 2 | 1 |
| horusec | `accounts.json` | 664 | 1 | 3 |
| grype | `openssl` | 640 | 80 | 2 |
| whispers | `run_results.xml` | 616 | 1 | 1 |
| whispers | `sc_alertlog_monitoring.sh` | 598 | 1 | 2 |
| grype | `curl` | 584 | 73 | 2 |
| retirejs | `plugin.min.js` | 580 | 1 | 1 |
| trivy-fs | `tailspend-analyzer.yaml` | 570 | 19 | 1 |
| whispers | `verify_secrets.yaml` | 554 | 1 | 108 |
| terrascan | `main.tf` | 549 | 13 | 21 |
| horusec | `cacert.pem` | 540 | 1 | 1 |
| horusec | `FBSDKCoreKit` | 512 | 2 | 2 |
| horusec | `consumerAccounts.json` | 480 | 1 | 1 |
| mobsf:android | `Siq5Popup.kt` | 465 | 1 | 1 |
| whispers | `GNU-Free-Documentation-License.html` | 448 | 1 | 2 |
| mobsf:android | `SleepNumberScreen.kt` | 440 | 1 | 1 |
| trivy-fs | `requirements.txt` | 430 | 47 | 13 |
| grype | `terraform.exe` | 425 | 84 | 1 |
| terrascan | `r-containers.tf` | 413 | 1 | 77 |
| mobsf:android | `SiqPopup.kt` | 410 | 1 | 2 |
| mobsf:android | `AppModule.kt` | 410 | 1 | 2 |
| horusec | `OpenAjaxManagedHub-all.js` | 408 | 6 | 1 |
| mobsf:android | `SmartBedErrorPopups.kt` | 405 | 1 | 1 |
| terrascan | `subnets.tf` | 389 | 1 | 2 |
| whispers | `packages.config` | 388 | 1 | 8 |
| whispers | `docker-compose.yml` | 384 | 23 | 25 |
| mobsf:android | `ConnectedDeviceInfo.kt` | 360 | 1 | 1 |
| mobsf:android | `Popups.kt` | 360 | 1 | 2 |
| grype | `Gemfile.lock` | 356 | 45 | 3 |
| whispers | `Environment-Variables.html` | 336 | 1 | 2 |
| whispers | `c_Whats_New_in_This_Release.html` | 324 | 1 | 1 |
| whispers | `deploymentTools.cfg` | 323 | 7 | 2 |
| grype | `datatable-dependencies-1.1.3.jar` | 315 | 63 | 1 |

## B. Widest defects under the current key

Critical, High and Medium only, not-actionable findings excluded — the
population that can be filed as a group. More than 10 projects is the
point at which an issue is recommended to be raised for the whole
organisation rather than one project. Showing 60.

| Scanner | Rule | Findings | Projects | Recommended scope |
| --- | --- | --- | --- | --- |
| trivy-fs | `Image user should not be 'root'` | 1,008 | 198 | organisation |
| horusec | `Potential Hard-coded credential` | 8,159 | 154 | organisation |
| horusec | `Hard-coded password` | 9,523 | 132 | organisation |
| grype | `GHSA-W5HQ-G745-H8PQ` | 643 | 110 | organisation |
| trivy-fs | `uuid: uuid: Out-of-bounds write vulnerability impacts data integrity and confidentiality` | 552 | 92 | organisation |
| terrascan | `reme_checkStorageContainerAccess` | 453 | 79 | organisation |
| trivy-fs | `Storage account should have infrastructure encryption enabled` | 1,311 | 66 | organisation |
| terrascan | `reme_storageAccountEnableHttps` | 295 | 56 | organisation |
| horusec | `Alert statements should not be used` | 6,147 | 50 | organisation |
| grype | `GHSA-F886-M6HF-6M8V` | 306 | 48 | organisation |
| trivy-fs | `node-jws: auth0/node-jws: Improper signature verification in HS256 algorithm` | 435 | 46 | organisation |
| grype | `GHSA-869P-CJFG-CM3X` | 435 | 46 | organisation |
| grype | `GHSA-FJXV-7RQG-78G4` | 311 | 46 | organisation |
| horusec | `No use weak random number generator` | 6,499 | 45 | organisation |
| grype | `GHSA-R5FR-RJXR-66JC` | 258 | 44 | organisation |
| grype | `GHSA-F23M-R3PF-42RH` | 248 | 44 | organisation |
| grype | `GHSA-3V7F-55P6-F55P` | 214 | 39 | organisation |
| grype | `GHSA-C2C7-RCM5-VVQJ` | 214 | 39 | organisation |
| grype | `GHSA-2MJP-6Q6P-2QXM` | 200 | 39 | organisation |
| grype | `GHSA-G9MF-H72J-4RW9` | 200 | 39 | organisation |
| grype | `GHSA-VRM6-8VPV-QV8Q` | 200 | 39 | organisation |
| grype | `GHSA-4992-7RV2-5PVQ` | 200 | 39 | organisation |
| grype | `GHSA-V9P9-HFJ2-HCW8` | 200 | 39 | organisation |
| horusec | `Password found in a hardcoded URL` | 1,264 | 38 | organisation |
| horusec | `Origins should be verified during cross-origin communications` | 1,250 | 38 | organisation |
| trivy-fs | `undici: Undici: HTTP header injection and request smuggling vulnerability` | 195 | 38 | organisation |
| trivy-fs | `undici: Undici: Denial of Service via excessive decompression steps` | 195 | 38 | organisation |
| trivy-fs | `undici: Undici: Denial of Service via invalid WebSocket permessage-deflate extension parameter` | 195 | 38 | organisation |
| trivy-fs | `undici: Undici: HTTP Request Smuggling and Denial of Service due to duplicate Content-Length headers` | 195 | 38 | organisation |
| trivy-fs | `undici: undici: Denial of Service via unbounded memory consumption during WebSocket permessage-deflate decompression` | 195 | 38 | organisation |
| grype | `GHSA-7R86-CG39-JMMJ` | 261 | 36 | organisation |
| grype | `GHSA-3PPC-4F35-3M26` | 261 | 36 | organisation |
| grype | `GHSA-23C5-XMQV-RM74` | 261 | 36 | organisation |
| trivy-fs | `form-data: Unsafe random function in form-data` | 261 | 35 | organisation |
| grype | `GHSA-XXJR-MMJV-4GPG` | 196 | 35 | organisation |
| grype | `GHSA-R4Q5-VMMM-2653` | 179 | 34 | organisation |
| trivy-fs | `brace-expansion: brace-expansion: Denial of Service via zero step value in brace pattern` | 213 | 33 | organisation |
| horusec | `AWS Secret Key` | 1,052 | 31 | organisation |
| horusec | `Asymmetric Private Key` | 1,902 | 30 | organisation |
| grype | `GHSA-QX2V-QP2M-JG93` | 190 | 30 | organisation |
| trivy-fs | `picomatch: Picomatch: Regular Expression Denial of Service via crafted extglob patterns` | 174 | 30 | organisation |
| trivy-fs | `picomatch: Picomatch: Data integrity compromised via method injection with crafted POSIX bracket expressions` | 174 | 30 | organisation |
| horusec | `Base64 Encode` | 677 | 29 | organisation |
| trivy-fs | `':latest' tag used` | 196 | 29 | organisation |
| trivy-fs | `lodash: lodash: Arbitrary code execution via untrusted input in template imports` | 175 | 28 | organisation |
| trivy-fs | `lodash: Lodash: Prototype pollution allows deletion of built-in prototype properties via array path bypass` | 165 | 28 | organisation |
| grype | `GHSA-72HV-8253-57QQ` | 150 | 28 | organisation |
| horusec | `No Default  Hash` | 5,067 | 27 | organisation |
| horusec | `SQL Injection` | 1,128 | 26 | organisation |
| grype | `GHSA-PMWG-CVHR-8VH7` | 167 | 26 | organisation |
| grype | `GHSA-6CHQ-WFR3-2HJ9` | 167 | 26 | organisation |
| grype | `GHSA-VF2M-468P-8V99` | 167 | 26 | organisation |
| grype | `GHSA-XX6V-RP6X-Q39C` | 167 | 26 | organisation |
| grype | `GHSA-62HF-57XW-28J9` | 167 | 26 | organisation |
| grype | `GHSA-5C9X-8GCM-MPGX` | 167 | 26 | organisation |
| grype | `GHSA-M7PR-HJQH-92CM` | 167 | 26 | organisation |
| grype | `GHSA-PF86-5X62-JRWF` | 167 | 26 | organisation |
| grype | `GHSA-W9J2-PVGH-6H63` | 167 | 26 | organisation |
| whispers | `password` | 426 | 25 | organisation |
| grype | `GHSA-GC5V-M9X4-R6X2` | 117 | 25 | organisation |

## C. Issues filed to AuditBoard from this system

`Findings covered` is the count measured when the issue was filed, not
today's count: findings deleted since then are not subtracted, because
the issue in AuditBoard still says what it said. A dash means the
column did not exist when that issue was filed — the first four were
filed under the retired grouping key, before per-project location lists
and defect identifiers were recorded. Issues raised in AuditBoard by
hand, or through its own screens, are not in this table; it records only
what this system filed.

| AuditBoard issue | Scope filed at | Scanner | Rule | Findings covered at filing | Projects | Locations listed | Locations omitted | Filed by | Filed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| I#1716 | global | whispers | `—` | 30 | — | — | 0 | ravance@gmail.com | 2026-09-15 |
| I#1717 | specific | horusec | `—` | 1 | — | — | 0 | ravance@gmail.com | 2026-09-15 |
| I#1718 | global | horusec | `—` | 304 | — | — | 0 | ravance@gmail.com | 2026-09-15 |
| I#1719 | global | horusec | `—` | 48 | — | — | 0 | ravance@gmail.com | 2026-09-15 |
| I#1720 | specific | grype | `—` | 1 | — | — | 0 | ravance@gmail.com | 2026-09-16 |

## D. Cross-scanner merge decisions recorded

A merge changes grouping only when it is both proposed as *equivalent*
and approved. Everything else in this table leaves the two scanners
reported separately.

| Rule A | Rule B | Proposed | Confidence | Review | Groups findings today | Model |
| --- | --- | --- | --- | --- | --- | --- |
| `horusec::Local File I/O Operations` | `mobsf:android::Weak Cryptography/Weak Crypto` | distinct | 0.99 | pending | no | cogdep-aifoundry-dev-eus2-claude-sonnet-4-6 |
| `terrascan::appArmorProfile` | `trivy-fs::Default security context configured` | distinct | 0.92 | pending | no | cogdep-aifoundry-dev-eus2-claude-sonnet-4-6 |
| `horusec::Asymmetric Private Key` | `trufflehog::PrivateKey` | distinct | 0.85 | pending | no | cogdep-aifoundry-dev-eus2-claude-sonnet-4-6 |

## E. Rule pairs not yet checked

Pairs from different scanners that report findings at the same file in
the same project. Co-location is why they are worth checking; it is not
evidence that they are the same problem.
Showing 60 of 475 unchecked pairs, widest overlap first.

| Rule A | Rule B | Shared places | Shared projects | Example path |
| --- | --- | --- | --- | --- |
| `terrascan::appArmorProfile` | `trivy-fs::Root file system is not read-only` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::appArmorProfile` | `trivy-fs::Runs as root user` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::appArmorProfile` | `trivy-fs::Seccomp policies disabled` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::imageWithoutDigest` | `trivy-fs::Default security context configured` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::imageWithoutDigest` | `trivy-fs::Root file system is not read-only` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::imageWithoutDigest` | `trivy-fs::Runs as root user` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::imageWithoutDigest` | `trivy-fs::Seccomp policies disabled` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::readOnlyFileSystem` | `trivy-fs::Default security context configured` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::readOnlyFileSystem` | `trivy-fs::Root file system is not read-only` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::readOnlyFileSystem` | `trivy-fs::Runs as root user` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::readOnlyFileSystem` | `trivy-fs::Seccomp policies disabled` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::runAsNonRootCheck` | `trivy-fs::Default security context configured` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::runAsNonRootCheck` | `trivy-fs::Root file system is not read-only` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::runAsNonRootCheck` | `trivy-fs::Runs as root user` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::runAsNonRootCheck` | `trivy-fs::Seccomp policies disabled` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::secCompProfile` | `trivy-fs::Default security context configured` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::secCompProfile` | `trivy-fs::Root file system is not read-only` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::secCompProfile` | `trivy-fs::Runs as root user` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::secCompProfile` | `trivy-fs::Seccomp policies disabled` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::securityContextUsed` | `trivy-fs::Default security context configured` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::securityContextUsed` | `trivy-fs::Root file system is not read-only` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::securityContextUsed` | `trivy-fs::Runs as root user` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::securityContextUsed` | `trivy-fs::Seccomp policies disabled` | 29 | 11 | `env/dev/app-template.yaml` |
| `terrascan::CpuRequestsCheck` | `trivy-fs::Default security context configured` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::CpuRequestsCheck` | `trivy-fs::Root file system is not read-only` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::CpuRequestsCheck` | `trivy-fs::Runs as root user` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::CpuRequestsCheck` | `trivy-fs::Seccomp policies disabled` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::CpulimitsCheck` | `trivy-fs::Default security context configured` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::CpulimitsCheck` | `trivy-fs::Root file system is not read-only` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::CpulimitsCheck` | `trivy-fs::Runs as root user` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::CpulimitsCheck` | `trivy-fs::Seccomp policies disabled` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::MemoryRequestsCheck` | `trivy-fs::Default security context configured` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::MemoryRequestsCheck` | `trivy-fs::Root file system is not read-only` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::MemoryRequestsCheck` | `trivy-fs::Runs as root user` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::MemoryRequestsCheck` | `trivy-fs::Seccomp policies disabled` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::MemorylimitsCheck` | `trivy-fs::Default security context configured` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::MemorylimitsCheck` | `trivy-fs::Root file system is not read-only` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::MemorylimitsCheck` | `trivy-fs::Runs as root user` | 28 | 11 | `env/dev/app-template.yaml` |
| `terrascan::MemorylimitsCheck` | `trivy-fs::Seccomp policies disabled` | 28 | 11 | `env/dev/app-template.yaml` |
| `horusec::AWS Manager ID` | `trufflehog::AWS` | 27 | 5 | `backend-service/src/main/docker/siqlt-backend-service.json` |
| `terrascan::appArmorProfile` | `trivy-fs::Can elevate its own privileges` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::imageWithoutDigest` | `trivy-fs::Can elevate its own privileges` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::privilegeEscalationCheck` | `trivy-fs::Can elevate its own privileges` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::privilegeEscalationCheck` | `trivy-fs::Default security context configured` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::privilegeEscalationCheck` | `trivy-fs::Root file system is not read-only` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::privilegeEscalationCheck` | `trivy-fs::Runs as root user` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::privilegeEscalationCheck` | `trivy-fs::Seccomp policies disabled` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::readOnlyFileSystem` | `trivy-fs::Can elevate its own privileges` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::runAsNonRootCheck` | `trivy-fs::Can elevate its own privileges` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::secCompProfile` | `trivy-fs::Can elevate its own privileges` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::securityContextUsed` | `trivy-fs::Can elevate its own privileges` | 26 | 10 | `env/dev/app-template.yaml` |
| `terrascan::CpuRequestsCheck` | `trivy-fs::Can elevate its own privileges` | 25 | 10 | `env/dev/app-template.yaml` |
| `terrascan::CpulimitsCheck` | `trivy-fs::Can elevate its own privileges` | 25 | 10 | `env/dev/app-template.yaml` |
| `terrascan::MemoryRequestsCheck` | `trivy-fs::Can elevate its own privileges` | 25 | 10 | `env/dev/app-template.yaml` |
| `terrascan::MemorylimitsCheck` | `trivy-fs::Can elevate its own privileges` | 25 | 10 | `env/dev/app-template.yaml` |
| `horusec::Hard-coded password` | `trufflehog::AzureAPIManagementSubscriptionKey` | 22 | 4 | `Siq.Common/Data/environments.json` |
| `terrascan::appArmorProfile` | `trivy-fs::Restrict container images to trusted registries` | 22 | 11 | `env/dev/app-template.yaml` |
| `terrascan::imageWithoutDigest` | `trivy-fs::Restrict container images to trusted registries` | 22 | 11 | `env/dev/app-template.yaml` |
| `terrascan::secCompProfile` | `trivy-fs::Restrict container images to trusted registries` | 22 | 11 | `env/dev/app-template.yaml` |
| `terrascan::readOnlyFileSystem` | `trivy-fs::Restrict container images to trusted registries` | 21 | 10 | `env/dev/app-template.yaml` |

