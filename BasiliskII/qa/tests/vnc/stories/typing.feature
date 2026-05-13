Feature: Type text into the guest UI over VNC
  User story: As a QA operator, I want to type text into a simple guest UI target
  so that keyboard injection and modifier handling can be tested repeatably.

  Background:
    Given the Finder desktop is visible over VNC

  Scenario: Type a short ASCII smoke string
    When the runner focuses target "typing-target"
    And the runner types text "BasiliskII QA smoke"
    Then a screenshot named "typing-smoke" is captured
    And the runner records manual assertion "typed text is visible or target is missing"
    And the emulator should still be running
