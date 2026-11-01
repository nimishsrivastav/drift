---
name: milestone
description: Restate a PLAN.md milestone's tasks and acceptance criteria, verify them, and tick its checkboxes.
argument-hint: "<milestone, e.g. M2>"
disable-model-invocation: true
---

# Milestone workflow for $ARGUMENTS

1. Read `PLAN.md` and `docs/DECISIONS.md`. Find the section for $ARGUMENTS.
   Check that earlier milestones are done, because milestones run in order. If one is not, say so and stop.
2. Restate the milestone's tasks and acceptance criteria, marking each as done, partly done or not started
   according to the repo, not the checkboxes.
3. Plan the remaining work, then build it one task at a time. After each task:
   - run that component's tests and lint
   - commit with a conventional-commit message
   - tick the task's checkbox in `PLAN.md`
4. Run the `acceptance-checker` agent to verify every acceptance criterion independently.
5. Report each criterion as met or not met, with the command and output that shows it. The milestone is done
   only when every criterion is demonstrably met. Never tick a box for work you did not verify.
6. If the plan turned out to be wrong, verify the current state, adjust, and log it in `docs/DECISIONS.md`.
