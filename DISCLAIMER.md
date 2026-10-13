# Disclaimer

This project is an **independent, unofficial** technical research project
that re-implements portions of the LeadSec V5VPN client by observing its
on-the-wire protocol and locally-stored credential format. It is **not**
affiliated with, endorsed by, sponsored by, or otherwise connected to:

- Beijing Leadsec Technology Co., Ltd. (Beijing Wangyu Xingyun)
- Hangzhou Anheng Information Technology Co., Ltd.
- Any other vendor whose software, trademarks, or service marks appear
  in connection with the V5VPN / SecUI / SecController product family.

All product names, trademarks, and registered trademarks mentioned in
this repository are the property of their respective owners. Reference
to those products in this repository is for descriptive and
interoperability purposes only and does not imply any endorsement or
authorization.

## What this project is

A desktop client that:

- Decodes the credential storage format used by the legacy V5VPN client
  (DES-CBC for passwords, Base64 for usernames) so that operators can
  recover their own credentials from machines they control.
- Speaks the documented HTTPS endpoints of the V5VPN SSL VPN gateway
  (`/vpn/version.xml`, `/vpn/user/auth/password`,
  `/vpn/user/portal/intergration.xml`, `/vpn/user/logout`) and tunnels
  TCP traffic through HTTP CONNECT over the gateway-provided session.
- Provides a MyGo-based GUI with system-tray integration and a
  localhost-only HTTP console as a fallback for browsers.

## What this project is not

- It is **not** a sanctioned or supported LeadSec product.
- It does **not** implement the original client's kernel-mode virtual
  network adapter (`SecTap.sys`, `ndislwf.sys`), IPsec, or the
  domestic-cipher (GM/SM2/SM3/SM4) suites. It cannot replace the
  official client for full-mesh routing scenarios.
- It does **not** ship a license to use any of the trademarks,
  protocols, or trade secrets of the original vendor. The DES key/IV
  and AES key/IV constants used to decode the legacy credential files
  are reproduced solely to enable interoperability with the user's own
  installation and must not be treated as a green light for any other
  use.

## Risks you accept by running this software

1. **Protocol disclosure is irreversible.** The constants, endpoints,
   field names, and flows reproduced in this repository are now public
   knowledge. The original vendor may harden the protocol in response,
   which will break this client without warning.
2. **Credential storage handling.** Storing credentials for automatic
   login reproduces the plaintext-on-disk problem that the original
   client suffers from. The bundled DES-CBC decoder is provided so that
   you can recover your own credentials from a machine you control; do
   not run it against any setting file you do not own or have
   permission to inspect.
3. **Compliance.** Confirm that your jurisdiction and your
   employer/customer agreements permit reverse engineering and
   interoperability research before deploying this software. Some EULAs
   explicitly prohibit reverse engineering; this project does not
   override such terms and is not a substitute for legal advice.

## No warranty

This software is provided under the Apache License 2.0 on an "AS IS"
basis, without warranty of any kind, express or implied. See
`LICENSE` for the full text. The contributors are not responsible for
any damage, data loss, account lockout, regulatory action, or other
harm arising from the use or misuse of this software.

By using this software you acknowledge that you have read this
disclaimer and accept the risks described above.
