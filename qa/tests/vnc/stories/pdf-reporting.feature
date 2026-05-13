Feature: PDF reporting from VNC QA artifacts
  User story: As a maintainer, I want VNC desktop QA to produce PDF reports from
  structured artifacts so that BasiliskII and SheepShaver runs can be reviewed
  and archived like the reports in rcarmo/vibes and rcarmo/go-rdp-android.

  Scenario: Generate a report from a completed VNC run
    Given a VNC run directory contains "vnc-run.json"
    And the run directory may contain screenshots or placeholder screenshots
    When the PDF report generator renders the run directory
    Then an HTML report should be written
    And a PDF report should be written when Playwright Chromium is available
    And the report should include scenario status, evidence tables, screenshots, and the VNC action log
