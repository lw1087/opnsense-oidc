# Changelog

## 0.3
- Use the claims of the verified ID token instead of the UserInfo endpoint (required for Microsoft Entra ID); UserInfo is opt-in.
- Fix discovery when the provider URL has no `.well-known/` path (#11).
- New options: fixed redirect URI, allowed tenant ID, match users by email (off by default), group claim, group mapping, group synchronization and required mapped group.
- Group membership is synchronized on every login for mapped groups only.
- Session id is regenerated after login; logins, denials and errors go to the audit log without exposing exception details to the browser.
- Created users get a random unusable password.
- CI: PHP lint and GitHub release on `v*` tags.

## 0.2
- Initial release.
