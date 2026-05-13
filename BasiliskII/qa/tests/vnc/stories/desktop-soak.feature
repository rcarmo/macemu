Feature: Desktop soak over VNC
  User story: As a JIT developer, I want the Mac desktop to remain responsive for
  a timed soak with optlev2 enabled so that native execution does not corrupt
  long-running UI state.

  Background:
    Given the Finder desktop is visible over VNC

  Scenario: Desktop remains reachable after a soak window
    Then a screenshot named "soak-start" is captured
    When the runner waits 600 seconds
    Then a screenshot named "soak-end" is captured
    And the VNC display should still respond
    And the emulator should still be running
    And the runner records manual assertion "no unbounded CPU/log anomaly without report entry"
