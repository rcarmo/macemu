Feature: BasiliskII desktop boot and basic UI reachability
  The emulator should boot a known-good Mac OS disk image to the Finder desktop
  under the selected CPU/JIT mode, expose a VNC-controllable display, and remain
  responsive enough to launch a simple app or control panel.

  Background:
    Given the BasiliskII binary has been built
    And the JIT vector preflight has passed
    And a known-good Quadra 800 ROM is available
    And a known-good Mac OS disk image is available

  Scenario: Boot optlev2 JIT to the Finder desktop
    Given QA case "optlev2-desktop-vnc" is selected
    When I start BasiliskII with VNC enabled
    Then the VNC server should accept a connection
    And a boot-progress screenshot should be captured
    And the Finder desktop should become visible before the timeout
    And a desktop screenshot should be captured
    And the emulator process should still be running

  Scenario: Launch a simple bundled application or control panel
    Given the Finder desktop is visible over VNC
    When I open the Apple menu or a known disk/folder location
    And I launch a simple bundled app or control panel
    Then the app window should become visible
    And an app-launched screenshot should be captured
    And keyboard and mouse input should remain responsive

  Scenario: Desktop soak remains responsive
    Given the Finder desktop is visible over VNC
    When I wait for the configured desktop soak duration
    Then the emulator should not crash
    And the VNC display should still update
    And a post-soak screenshot should be captured
    And log anomalies should be recorded in the QA report
