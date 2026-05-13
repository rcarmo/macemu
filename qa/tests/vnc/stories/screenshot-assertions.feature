Feature: Deterministic screenshot assertions for CI
  User story: As a CI maintainer, I want desktop tests to read screenshots with
  deterministic image processing, OCR, and template matching instead of model
  vision so that BasiliskII and SheepShaver QA can run unattended.

  Background:
    Given the emulator desktop is visible over VNC

  Scenario: Captured desktop screenshot has deterministic image properties
    Then a screenshot named "desktop-assertion" is captured
    And the screenshot named "desktop-assertion" should have dimensions 640 by 480
    And the screenshot named "desktop-assertion" should not be blank

  Scenario: Optional OCR can identify expected UI text
    Then a screenshot named "ocr-target" is captured
    And OCR text from screenshot "ocr-target" should contain "Finder"

  Scenario: Optional OpenCV template matching can find known UI elements
    Then a screenshot named "template-target" is captured
    And the screenshot named "template-target" should match template "qa/tests/vnc/templates/finder-menu.png" with threshold 0.90
