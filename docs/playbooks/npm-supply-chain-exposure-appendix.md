# Appendix — the specific names

## How to read this appendix

The briefing deliberately uses counts rather than names — the names crowd out the
argument for a reader who does not own any of these repositories.

This appendix is the other half: **every count in the briefing, resolved to the
things a team would actually open and change.** It is generated from the same
collector artifacts the technical report reads, not typed by hand, so it cannot
drift from them.

Anything listed here is something we read directly. Where a population could not
be read at all, it is named at the end as a gap rather than left out.

## Problem 1a — build components handed the whole keyring

**5** components are passed `toJSON(secrets)` — the complete secrets object — across **1,929** pipeline references. **4** of them are tracked by a moving name rather than an exact version, covering **1,924** of those references. The one pinned to a long commit reference is safer against tampering but still receives everything.

| Build component handed every secret | Pipeline refs | Shared workflows | Deploys |
|---|---:|---:|---:|
| `terraform-setup-composite-action@v2` | **1,904** | 40 | yes |
| `terraform-setup-composite-action@v1` | **18** | 8 | yes |
| `Firenza/secrets-to-env@7da604dcd013382fa0b2c9b6aeb33400f10bf322` | **5** | 1 | — |
| `Firenza/secrets-to-env@v1.3.0` | **1** | 1 | — |
| `secrets-to-tfvars-file-creator@v1` | **1** | 1 | yes |

## Problem 1b — shared processes handed the whole keyring (1 of 2)

A second mechanism, and a separate fix: **11** shared processes are called with `secrets: inherit`, which passes everything the caller holds without naming any of it. **1,363** pipeline references. Almost all of these deploy.

| Shared process handed every secret | Pipeline refs | Callers | Deploys |
|---|---:|---:|---:|
| `terraform-format-gha-workflow › terraform_format.yaml@v1` | **278** | 12 | yes |
| `terraform-security-gha-workflow › terraform_security.yaml@v1` | **275** | 11 | yes |
| `check-destroy-workflow › check_destroy.yaml@v1` | **252** | 10 | yes |
| `semantic-release-deployment-workflow › semantic_release_deployment.yaml@v1` | **246** | 6 | yes |
| `promote-release-and-deployment-workflow › promote_release_and_deployment.yaml@v1` | **245** | 9 | yes |
| `terraform-testing-workflows › test_terraform.yml@v1` | **42** | 2 | — |

## Problem 1b — shared processes handed the whole keyring (2 of 2)

| Shared process handed every secret | Pipeline refs | Callers | Deploys |
|---|---:|---:|---:|
| `terraform-testing-workflows › test_terraform.yml@v2` | **10** | 2 | yes |
| `cicd-workflows › promote_release_and_deployment.yml@v1` | **6** | 4 | yes |
| `audit-github-scanner-workflow › scan.yaml@v1` | **3** | 1 | — |
| `ado-work-item-check › check_commit.yaml@v1` | **3** | 2 | yes |
| `ado-work-item-update › update_work_item.yaml@v1` | **3** | 2 | yes |

## Problem 1c — steps that print the keyring into the shell

**2** steps expand the whole secrets object into the runner's own command line in order to read the *names* off it — **214** pipeline references. Reading names never requires handling values, so this one is a rewrite rather than a narrowing.

| Step that expands secrets into the build shell | Pipeline refs | Deploys |
|---|---:|---:|
| `verify-secrets-dev:Get secret JSON keys` | **107** | — |
| `verify-secrets-all-env:Get secret JSON keys` | **107** | — |

## Problem 1 — where the change lands

Three mechanisms, three different edits. All of them live in
`.github/workflows/<name>.yaml` in the shared repository, not in the consumers.
For 1a and 1b there is a second step: pin the target to a commit reference instead of
`@v1` / `@v2`, and turn on tag protection in the target's own repository so the name
cannot be moved.

| Mechanism | What to look for | What to replace it with |
|---|---|---|
| **1a** | `${{ toJSON(secrets) }}` in a `with:` block | the specific secrets that step reads, named one per line |
| **1b** | `secrets: inherit` under a `uses:` call | a `secrets:` block naming only what the called process needs |
| **1c** | `toJSON(secrets)` inside a `run:` script | an approach that lists secret names without expanding their values |

## Problem 1 — the shared workflows that pass it onward (largest of 46) (1 of 2)

**46** definitions pass the whole secrets context to whatever called them, reaching **1,823** consumer references. **37** of them deploy. The full 46 are in `exports/hunt/reusable_workflow_targets.json`; these are the largest.

| Shared workflow | Ref | Consumers | Deploys |
|---|---:|---:|---:|
| `terraform-delete-gha-workflow › delete_resource.yaml` | `v2` | **246** | yes |
| `terraform-unlock-gha-workflow › unlock_state.yaml` | `v2` | **246** | yes |
| `terraform-rename-gha-workflow › rename_resource.yaml` | `v2` | **246** | yes |
| `terraform-import-gha-workflow › import_resource.yaml` | `v2` | **246** | yes |
| `verify-secrets-gha-workflow › verify_secrets.yaml` | `v1` | **107** | — |
| `terraform-infra-ci-gha-workflow › terraform_ci.yaml` | `v2` | **103** | yes |
| `terraform-infra-cd-gha-workflow › terraform_cd.yaml` | `v2` | **96** | yes |
| `pr-comment-deploy-managed-api-gha-workflow › pr_comment_deploy.yaml` | `v2` | **67** | yes |

## Problem 1 — the shared workflows that pass it onward (largest of 46) (2 of 2)

| Shared workflow | Ref | Consumers | Deploys |
|---|---:|---:|---:|
| `managed-api-ci-gha-workflow › managed-api-ci.yaml` | `v2` | **67** | yes |
| `managed-api-cd-gha-workflow › managed-api-cd.yaml` | `v2` | **66** | yes |
| `pr-comment-deploy-function-app-gha-workflow › pr_comment_deploy.yaml` | `v2` | **60** | yes |
| `node-function-app-ci-gha-workflow › node-function-app-ci.yaml` | `v2` | **55** | yes |
| `node-function-app-cd-gha-workflow › node-function-app-cd.yaml` | `v3` | **54** | yes |
| `terraform-destroy-gha-workflow › destroy.yaml` | `v1` | **39** | yes |
| `terraform-module-ci-gha-workflow › terraform_module_ci.yaml` | `v1` | **21** | — |
| `node-multi-deployment-function-app-ci-gha-workflow › node-multi-deployment-function-app-ci.yaml` | `v2` | **13** | yes |

## Problem 1 — the remaining shared workflows (1 of 2)

The other 30 definitions, each passing the whole secrets context onward. Smaller consumer counts, same mechanism.

| | |
|---|---|
| `node-multi-deployment-function-app-cd-gha-workflow@v4` | `pr-comment-deploy-multi-deployment-function-app-gha-workflow@v2` |
| `static-web-app-cd-gha-workflow@v1` | `java-maven-ci-gha-workflow@v2` |
| `logic-app-ci-gha-workflow@v1` | `terraform-module-ci-gha-workflow@v2` |
| `logic-app-cd-gha-workflow@v1` | `pr-comment-deploy-logic-app-gha-workflow@v1` |
| `container-app-ci-gha-workflow@v1` | `container-app-cd-gha-workflow@v1` |
| `terraform-delete-gha-workflow@v1` | `terraform-import-gha-workflow@v1` |
| `terraform-rename-gha-workflow@v1` | `terraform-unlock-gha-workflow@v1` |
| `xslt-mapping-cd-gha-workflow@v1` | `xslt-mapping-ci-gha-workflow@v1` |

## Problem 1 — the remaining shared workflows (2 of 2)

| | |
|---|---|
| `terraform-infra-cd-gha-workflow@v1` | `terraform-infra-ci-gha-workflow@v1` |
| `web-app-cd-gha-workflow@v2` | `web-app-ci-gha-workflow@v2` |
| `java-maven-ci-gha-workflow@secrets-to-env-vars` | `logic-app-cd-gha-workflow@add-copilot-agent-fix` |
| `node-function-app-cd-gha-workflow@new-test` | `node-function-app-cd-gha-workflow@v2` |
| `node-function-app-ci-gha-workflow@v1` | `pr-comment-deploy-function-app-gha-workflow@main` |
| `pr-comment-deploy-infra-gha-workflow@v1` | `pr-comment-deploy-managed-api-gha-workflow@test-update4` |
| `python-function-app-ci-gha-workflow@initial-creation` | `terraform-destroy-gha-workflow@initial-code` |

## Problem 2 — projects that run supplier code on sight (1 of 5)

All **94** of them. Each needs `--ignore-scripts` on its install command, or `ignore-scripts=true` in an `.npmrc` committed at the repository root.

| | |
|---|---|
| `SleepNumber/.com` | `SleepNumber/actions-sandbox` |
| `SleepNumber/sleepcms` | `SleepNumber/sndotcom` |
| `SleepNumber/vtex-boilerplate-app` | `SleepNumberInc/App-Factory-Trial` |
| `SleepNumberInc/Azure-Function-Node-POC` | `SleepNumberInc/Azure-Integrations-Managed-APIs` |
| `SleepNumberInc/AzureIntegration` | `SleepNumberInc/ProductCatalogLogicAppsTests` |
| `SleepNumberInc/SCM-Supplier-Stock-Automation-fna` | `SleepNumberInc/Workforce-Mgmt-Managed-APIs` |
| `SleepNumberInc/authorize` | `SleepNumberInc/aws-waf-blocked-ip-ruleset-cron` |
| `SleepNumberInc/cognito-user-pool-maintenance` | `SleepNumberInc/common-logging-test` |
| `SleepNumberInc/cryptex` | `SleepNumberInc/custom-logger` |
| `SleepNumberInc/dev-js-config` | `SleepNumberInc/devops-github-org-webhook-processor` |

## Problem 2 — projects that run supplier code on sight (2 of 5)

| | |
|---|---|
| `SleepNumberInc/docker-swarm-service-balancer` | `SleepNumberInc/dot-env-to-env-var-action` |
| `SleepNumberInc/ebs-order-integration` | `SleepNumberInc/exp-ingestion-api` |
| `SleepNumberInc/exp-sbn-api` | `SleepNumberInc/expired-secrets-exterminator` |
| `SleepNumberInc/gcc-creative-studio` | `SleepNumberInc/gh-token-rate-limit-monitor` |
| `SleepNumberInc/github-runner-group-usage-monitor` | `SleepNumberInc/github-token-rate-limit-monitor` |
| `SleepNumberInc/java-linter-output-formatter` | `SleepNumberInc/javascript-github-action-template` |
| `SleepNumberInc/job-data-updater` | `SleepNumberInc/node-cron-docker` |
| `SleepNumberInc/nodejs-microservice-template` | `SleepNumberInc/nodejs-microservice-utils` |
| `SleepNumberInc/npm-package-cd-workflow` | `SleepNumberInc/npm-package-ci-workflow` |
| `SleepNumberInc/opentelemetry-js-agent` | `SleepNumberInc/opentelemetry-plugin-nestjs-rabbitmq` |

## Problem 2 — projects that run supplier code on sight (3 of 5)

| | |
|---|---|
| `SleepNumberInc/order-status-poc-api` | `SleepNumberInc/proc-product-catalog` |
| `SleepNumberInc/product-catalog-e2e` | `SleepNumberInc/product-exchange-backend` |
| `SleepNumberInc/product-exchange-frontend` | `SleepNumberInc/pulse-sandbox` |
| `SleepNumberInc/scm-poc-fna` | `SleepNumberInc/scmtstfuncapp` |
| `SleepNumberInc/sec-diligence` | `SleepNumberInc/secret-server-secret-retriever` |
| `SleepNumberInc/secrets-to-tfvars-file-creator` | `SleepNumberInc/servicenow-devops-change` |
| `SleepNumberInc/sharedsvc-notification-webhook-fna` | `SleepNumberInc/sn-identity-auth-test-ui` |
| `SleepNumberInc/sn-vare-product-exchange-backend` | `SleepNumberInc/sn-vare-product-exchange-frontend` |
| `SleepNumberInc/snint-azure-gop-fna` | `SleepNumberInc/snint-contact-merges-siebel-publisher-fna` |

## Problem 2 — projects that run supplier code on sight (4 of 5)

| | |
|---|---|
| `SleepNumberInc/snint-customer-lookup-process-api-fna` | `SleepNumberInc/snint-customer-orders` |
| `SleepNumberInc/snint-ds-k6-load-tests` | `SleepNumberInc/snint-ebs-inventory-pollers-fna` |
| `SleepNumberInc/snint-employees-api` | `SleepNumberInc/snint-employees-d365-consumer-fna` |
| `SleepNumberInc/snint-employees-mapper-api` | `SleepNumberInc/snint-fn-test-sftp-onpremise-dev` |
| `SleepNumberInc/snint-incidents-d365-consumer-fna` | `SleepNumberInc/snint-incidents-d365-customer-lookup-fna` |
| `SleepNumberInc/snint-incidents-digital-publisher-apim` | `SleepNumberInc/snint-incidents-digital-publisher-fna` |
| `SleepNumberInc/snint-invision-mappings` | `SleepNumberInc/snint-logs-poc-fna` |
| `SleepNumberInc/snint-logs-poc2-fna` | `SleepNumberInc/snint-logs-without-ai-poc-fna` |
| `SleepNumberInc/snint-pim-api-fna` | `SleepNumberInc/snint-pim-conn-fna` |

## Problem 2 — projects that run supplier code on sight (5 of 5)

| | |
|---|---|
| `SleepNumberInc/snint-products-fna` | `SleepNumberInc/snint-stores-siebel-publisher-fna` |
| `SleepNumberInc/snip-cli` | `SleepNumberInc/snip-e2e-ui-poc` |
| `SleepNumberInc/snmspsal-ai-sales-trainer-backend-fna` | `SleepNumberInc/snoint-azure-integrations-order-fna` |
| `SleepNumberInc/snoint-siebel-gop-api-fna` | `SleepNumberInc/sys-product` |
| `SleepNumberInc/sys-rule` | `SleepNumberInc/terratest-json-output-fixer` |
| `SleepNumberInc/test-microservice` | `SleepNumberInc/test-ms-template` |
| `SleepNumberInc/test-ms-template2` | `SleepNumberInc/test-results-file-to-qtest-action` |
| `sleepnumberlabs/poc-john-merrill-testing` | `sleepnumberlabs/qa-sn-playwright-automation` |
| `sleepnumberlabs/web-consumer-sleepiq` | `sleepnumberlabs/web-support-portal` |

## Problem 2 — the projects that already refuse

**5** repositories are already protected, covering **6** workflows. They are the pattern to copy — the change is already written and reviewed inside our own estate.

| Repository | How it is protected |
|---|---:|
| `SleepNumberInc/chads-github-actions-playground` | `.npmrc` config |
| `SleepNumberInc/sn-identity` | every installing workflow |
| `SleepNumberInc/snint-ds-e2e-testcases` | every installing workflow |
| `SleepNumberInc/snint-marketing-campaign-e2e-testcases` | every installing workflow |
| `SleepNumberInc/snip-auth-service-e2e-testcases` | every installing workflow |

## Problem 2 — where the change lands

- **In a workflow:** `.github/workflows/<name>.yml` — add `--ignore-scripts` to the
  `npm ci` / `npm install` / `yarn` / `pnpm` line
- **Or, better, once per repository:** create `.npmrc` at the repository root
  containing `ignore-scripts=true`, which covers every install including a
  developer's laptop

The second form is preferred: it is one file, it is reviewable, and it protects the
surface the first form does not.

## Problem 3 — the vacant addresses

**9 references across 12 consumer calls** point at these branch names in central workflow repositories. The repositories exist; the branches were verified deleted. Two names carry more than one reference, which is why nine references map to eight distinct names.

| Branch name being called | Status |
|---|---:|
| `initi` | deleted — claimable |
| `use-environment` | deleted — claimable |
| `add-copilot-blocker` | deleted — claimable |
| `feat/extra-node-ca-cert` | deleted — claimable |
| `update-to-node-24-actions` | deleted — claimable |
| `multipe-primary-image-versions` | deleted — claimable |
| `update-provider-inputs` | deleted — claimable |
| `dependabot-fixes` | deleted — claimable |

## Problem 3 — who is calling them, and what to do

**Consumers that are not sandboxes** — these break today and are the escalation path:

- `SleepNumberInc/snip-iics-mft-ops`
- `SleepNumberInc/dot-env-to-env-var-action`
- `SleepNumberInc/eslint-config-azure-integrations`

The rest are sandbox and proof-of-concept repositories (`cldsvcs-test-*`,
`devops-sandbox-*`, `ss_gh_poc`, `chads-github-actions-playground`).

**Two more are ordinary breakage rather than risk:** `snip-iics-mft-ops` calls
`iics_cd_workflow.yaml@main` where the file is now `iics_cd.yaml`, and two repos call
`pr_lint.yml@v1` where the file is `pr_lint.yaml`.

**The fix has two halves, and both are required.** Repoint the `uses:` line at a commit
SHA on a branch that exists — then add a branch protection rule in the *central*
repository matching each deleted name, and restrict branch creation to maintainers.
Repointing alone leaves the door shut but unlocked.

## Problem 4 — the most-referenced moving targets

**8,115** references sit on a moving name against **960** pinned to an exact version. These twelve are where pinning buys the most.

| Outside component tracked on a moving name | References |
|---|---:|
| `FranzDiebold/github-env-vars-action@v2.1.0` | **233** |
| `hashicorp/setup-terraform@v1` | **162** |
| `c-py/action-dotenv-to-setenv@v3` | **111** |
| `chrnorm/deployment-action@releases/v1` | **92** |
| `ncipollo/release-action@v1` | **73** |
| `Azure/docker-login@v1` | **70** |
| `montudor/action-zip@v0.1.1` | **63** |
| `notiz-dev/github-action-json-property@release` | **62** |
| `rsotnychenko/deployment-status-update@0.2.0` | **60** |
| `jossef/action-set-json-field@v1` | **55** |
| `Azure/container-scan@v0` | **52** |
| `Firenza/secrets-to-env@v1.1.0` | **52** |

## Problem 4 — workflows that download and run code without checking it

Four workflows fetch code from the internet and execute it immediately. This is deliberate in each case, but it is the same primitive the campaign relies on, so each should be pinned to a known version or replaced.

| Repository | File | Occurrences |
|---|---:|---:|
| `sleep-number-claude-code-plugins` | `.github/workflows/ci.yaml` | 2 |
| `sleepnumberlabs/sdna-new-databricks` | `.github/workflows/1-sync-databricks-jobs.yml` | 1 |
| `sleepnumberlabs/sdp-databricks-pytest-poc` | `.github/workflows/run-integration-tests.yml` | 1 |
| `sleepnumberlabs/sdp-databricks-pytest-poc` | `.github/workflows/run-tests-on-databricks-dev.yml` | 1 |

## Fix E — the front door we already own

**0** relevant components flow through any of these, against **523** Microsoft-ecosystem components that do. The connection already exists on three of them.

| Feed | Connected to the public catalog | Readable |
|---|---:|---:|
| `sn-tim/sn-tim` | yes | yes |
| `sn-tim/sn-tim-invision-packages` | no | yes |
| `sn-tim/sn-tim-packages` | yes | yes |
| `SleepNumberIndigo/k8s-manifests` | no | **no** |
| `SleepNumberIndigo/SleepNumberIndigo` | yes | yes |

## What is deliberately not listed here

- **193 projects** where the download
  step happens inside something we did not read. They are neither safe nor unsafe in
  this appendix, because we do not know.
- **265 projects** with no automated install at all,
  **73** of them with no automation whatsoever.
  Their components are only ever downloaded on a person's own laptop.
- **2 repositories** whose file listing was cut short by
  GitHub: `SleepNumberInc/Github_PBI_Integrated_Workspaces`, `sleepnumberlabs/siqassess`.
- **One internal feed we could not read** — `SleepNumberIndigo/k8s-manifests` — for
  permission reasons. A request naming the exact permission is in the technical report.
- **The 838 workflows that put secret values into a command line.** The collector
  records the first 200; listing a truncated set here would read as a complete one.

*Generated by `scripts/report/build_appendix.py` from the collector artifacts in*
*`exports/hunt/`. Re-run it rather than editing this file.*
