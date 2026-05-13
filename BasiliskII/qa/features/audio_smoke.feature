Feature: BasiliskII audio smoke coverage
  Audio QA should cover the stable nosound baseline, SDL dummy automation path,
  and real audio output when host hardware is available.

  Scenario: Nosound baseline is stable
    Given QA case "optlev2-rom-smoke" or "optlev2-desktop-vnc" is selected
    And prefs contain "nosound true"
    When the emulator runs through the configured smoke window
    Then no audio initialization failure should be present in the logs
    And the run should be evaluated only for emulator stability, not audible sound

  Scenario: SDL dummy audio initializes for headless automation
    Given QA case "optlev2-audio-dummy" is selected
    And "SDL_AUDIODRIVER=dummy" is set
    And prefs contain "nosound false"
    When the emulator boots
    Then SDL audio initialization should not crash the emulator
    And any warning should be recorded in the QA report

  Scenario: Real audio output is manually tested
    Given host audio hardware and permissions are available
    And QA case "optlev2-audio-real" is selected
    When Mac OS plays a boot chime, system beep, or app sound
    Then the operator should record whether sound was heard
    And the SDL audio driver/device should be recorded
