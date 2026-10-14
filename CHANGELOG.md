# Changelog

## 0.1.0

Initial public release.

- Password login against V5VPN SSL VPN gateways (protocol v2.0).
- Pull authorized TCP/UDP resources from /vpn/user/portal/intergration.xml.
- HTTP CONNECT tunnel proxy through the gateway with VSG_SESSIONID cookie.
- Heartbeat / keepalive probe.
- Safe logout via /vpn/user/logout.
- MyGo desktop window with adaptive sizing (460x700 login, 720x620
  gateway manager, 1248x832 connected workspace).
- System tray with connection-state icon and right-click menu.
- GitHub Star footer on login and connected views (opens the repo in
  the system browser).
- ed25519-signed self-update from GitHub releases (tray "Check for
  updates...", ~10s after launch).
- Local HTTP bridge at http://127.0.0.1:<port> for browser fallback.
- Credential recovery: -dump-passwords reads and decrypts legacy
  setting.xml / setting.ini from the current directory or the
  executable directory.
- CLI mode: -cli -connect <gateway> -user <u> -pwd <p>.
- README, DISCLAIMER, NOTICE and configs/setting.xml.example so
  operators can bootstrap without checking production data into VCS.
