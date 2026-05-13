Feature: Launch a simple Mac OS app over VNC
  User story: As a QA operator, I want to launch a simple bundled app or control
  panel from the Finder desktop so that mouse/keyboard input, window drawing,
  and basic event loop responsiveness are verified.

  Background:
    Given the Finder desktop is visible over VNC

  Scenario: Open a control panel or simple app
    When the runner clicks target "apple-menu"
    And the runner clicks target "control-panels-or-simple-app"
    Then the runner waits for display state "app-window-visible" for 60 seconds
    And a screenshot named "app-launched" is captured
    And the emulator should still be running

  Scenario: Close or leave the app in a known state
    Given a simple app window is visible
    When the runner sends key "Command+W"
    Then a screenshot named "app-closed-or-known-state" is captured
