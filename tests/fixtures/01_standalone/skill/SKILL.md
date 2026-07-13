---
name: standalone-tool
description: Standalone skill with a complete local payload
requires:
  bins:
    - git
    - docker
  env:
    - WORKSPACE_ID
---
Read the [local guide](references/guide.md).
Use the [bundled payload](assets/payload.txt).
The local validation payload is `scripts/never-run.sh`.
