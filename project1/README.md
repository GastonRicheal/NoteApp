# Project 1: NotesApp threat model and risk analysis

**Author: ZHANG FANGYUCHEN.** Only this author has been confirmed for Project 1;
no additional members or contributions are claimed. The course brief specifies
groups of 3-4, so the current one-person authorship needs instructor agreement.

This project records the application review of **9 October 2026**, including
Session 3 comment encryption. It is not a new audit of later Class 4/5 changes.

## Required deliverables

- [English report](REPORT.md): numbered DFD flows and all trust boundaries,
  STRIDE coverage, likelihood x impact scores, and fixes for the top three risks.
- [Final PDF report](output/NotesApp-Project1-Report.pdf).
- [Final editable presentation](output/NotesApp-Project1-Presentation.pptx):
  six slides for the course's three-minute presentation.
- [Presentation notes](PRESENTATION_NOTES.md).
- [Structured threat model](threat_model.json): 16 threats, 20 flows, six boundaries.
- [Application DFD](diagrams/application-dfd.svg) and
  [deployment DFD](diagrams/deployment-dfd.svg).
- [Read-only runtime evidence](evidence/runtime-observations.txt) and
  [reviewed-source fingerprints](evidence/source-manifest.json).

Only final report/presentation versions and their supporting model/evidence are
included. Local authoring scripts, renders, intermediate decks, runtime secrets
and student database exports are excluded.

## Findings and interpretation

The top priorities are login SQL injection (25/25), shell/Docker control (20/25),
and a public session signing key (20/25). Fixes and acceptance criteria are
proposals; the report does not claim these teaching flaws have been repaired.
AES-GCM storage does not enforce ownership or prevent stored HTML execution.

Scores are qualitative judgments on 1-5 likelihood and impact scales, not CVSS
or measured probabilities. Ties are resolved by impact and control scope.
Source fingerprints identify the original reviewed working tree. Subsequent
source changes do not rewrite the dated report or its historical observations.

The brief (Session 03, slide 31) requests GitHub hand-in before 20 October and a
three-minute presentation on that day. This later repository update does not
claim that the original deadline or group-size condition was satisfied.
