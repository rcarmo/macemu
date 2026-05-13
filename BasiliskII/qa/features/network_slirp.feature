Feature: BasiliskII network smoke via safe user-mode backend
  Network QA should first attempt a non-privileged slirp configuration before
  requiring tap/tun setup or host networking changes.

  Background:
    Given the BasiliskII binary has been built with network support
    And the QA runner can enable the "ether slirp" preference
    And desktop VNC automation is available

  Scenario: Guest can see an emulated Ethernet interface
    Given QA case "optlev2-network-slirp" is selected
    When I boot Mac OS to the desktop
    And I open the relevant network configuration panel
    Then the guest should show an Ethernet or TCP/IP-capable interface
    And the network configuration screenshot should be captured

  Scenario: Guest attempts host-local connectivity
    Given a host-local test service has been started
    And the guest network stack is configured
    When I attempt connectivity from the guest to the local service
    Then the attempt result should be recorded as pass, fail, or blocked
    And logs should distinguish emulator failure from missing guest tools/assets

  Scenario: Privileged network backends are not used by default
    Given tap or tun networking would require host privilege changes
    Then the default QA matrix should mark those paths as manual/approved-only
    And no privileged host network changes should be made automatically
