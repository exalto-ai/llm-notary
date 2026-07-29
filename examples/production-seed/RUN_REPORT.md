# Production examples execution report

Status: **not run**. The publication stack must be reviewed, merged, deployed,
and released first.

Released CLI version:

Source commit:

Production deploy:

Platform key ID:

## Per-task results

For every task in `tasks.json`, record:

- task ID
- exact model and API surface
- streaming and tool-use behavior observed
- disposable fixture path description (never a personal absolute path)
- selected bundle capture ID
- finalization duration and retry count
- automated disclosure scan result
- manual request/response/trace review result
- publication job ID and terminal state
- public trace and stamp URLs
- independent verification result
- any bug or linked blocking issue

## Final checklist

- [ ] Ten admitted publications cover all five requested surfaces.
- [ ] All artifacts passed independent released-CLI verification.
- [ ] No credential, cookie, token, personal path, email address, or unrelated
      session identifier was disclosed.
- [ ] Provider/model/tool ordering/system context/usage fields were reviewed.
- [ ] `publications.json` contains only admitted production IDs.
- [ ] The production collection and every download link were checked.
