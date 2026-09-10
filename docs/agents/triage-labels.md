# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                   |
| --------------------------- | ---------------------- | ------------------------------------------ |
| `needs-triage`               | `needs-triage`         | Maintainer needs to evaluate this issue    |
| `needs-info`                 | `needs-info`           | Waiting on reporter for more information   |
| `ready-for-agent`            | `ready-for-agent`      | Fully specified, ready for an AFK agent    |
| `ready-for-human`            | `human-needed`         | Requires human implementation              |
| `wontfix`                    | `wontfix`               | Will not be actioned                       |

Note: this repo also has `needs-human` ("blocked pending a human decision; excluded from agent dispatch") — a narrower role than `ready-for-human`. Skills in this suite never apply `needs-human`; it stays a manual/other-tooling label.

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.
