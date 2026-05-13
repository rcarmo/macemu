Feature: Classic Mac desktop reachability over VNC
  User story: As a JIT developer, I want BasiliskII or SheepShaver to boot a
  known Mac OS disk image to the classic Mac desktop over VNC so that I can
  verify system-level behaviour beyond ROM/CPU smoke tests.

  Background:
    Given the emulator profile has generated desktop QA prefs
    And the emulator is launched with VNC enabled
    And the runner records emulator profile

  Scenario: VNC connects and the desktop becomes visible
    When the VNC runner connects to the emulator display
    Then a screenshot named "vnc-connected" is captured
    When the runner waits for display state "boot-progress" for 120 seconds
    Then a screenshot named "boot-progress" is captured
    When the runner waits for display state "finder-desktop" for 300 seconds
    Then a screenshot named "finder-desktop" is captured
    And the emulator should still be running

  Scenario: Failure diagnostics are collected when desktop is not reached
    When the runner waits for display state "finder-desktop" for 300 seconds
    And the display state is not reached
    Then a screenshot named "desktop-timeout" is captured
    And the runner records failure classification "unknown"
    And the runner records emulator logs and prefs paths
