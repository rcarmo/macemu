Feature: Inspect network configuration over VNC
  User story: As a network QA operator, I want to open the relevant Mac OS
  networking control panel with `ether slirp` enabled so that I can confirm
  whether the guest sees an emulated Ethernet/TCP/IP interface before attempting
  connectivity.

  Background:
    Given the QA case "optlev2-network-slirp" has generated prefs
    And the Finder desktop is visible over VNC

  Scenario: Open network configuration UI
    When the runner clicks target "apple-menu"
    And the runner opens guest item "TCP/IP-or-Network-control-panel"
    Then the runner waits for display state "network-panel-visible" for 60 seconds
    And a screenshot named "network-panel" is captured
    And the runner records manual assertion "Ethernet or TCP/IP interface is visible, or guest assets are missing"

  Scenario: Record blocked network assets clearly
    Given the network control panel cannot be found
    Then a screenshot named "network-panel-missing" is captured
    And the runner records failure classification "missing guest asset"
