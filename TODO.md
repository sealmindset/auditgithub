# TODO — AuditGH

## Security
- [ ] Address Dependabot alerts: 5 high + 11 moderate on SleepNumberInc remote, 3 high + 10 moderate on sealmindset remote
- [x] Run `/fix-it medium` — 15 of 18 MEDIUM findings resolved (2026-05-22)
- [ ] postcss XSS vulnerability (transitive via next) — awaiting Next.js patch, no safe upgrade path
- [ ] Run `/fix-it all` to clear remaining LOW (5) + INFO (2) findings
- [ ] Fix pre-existing TypeScript error in `components/APIAuditView.tsx:1052` (`external_url` property)
- [ ] Merge `security-workstation` branch to `main` when ready

## Docs
- [ ] Review and commit `docs/EA_Design_Pattern_AWS_Bedrock.md` and `docs/EA_Design_Pattern_MakeIt.md` (untracked)

## Cleanup
- [ ] Review `.scan_resume_state.pkl` — commit or add to .gitignore
