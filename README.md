# OpenID Connect for OPNsense
This package will allow you and your administrators to login to the OPNsense dashboard with a OpenID Connect provider.

![img of settings](https://i.lu.je/2025/Discord_gfAMDTPfun.png)

# Installation
Download the package from releases and install on your opnsense via the console:
```
pkg add os-oidc-0.3.pkg
```

## Configuration
### Provider Url
This is a link to the provider. The URL will need to have `/.well-known/openid-configuration` available for discovery.

### Client ID
The provided ID from your OIDC provider

### Client Secret
The secret from your OIDC provider

### Username Claim
The field from the user payload that contains the username.

### Scopes
Scopes to request form the OIDC Provider. For example, `openid`, `email`, `profile`.

### Automatic user creation
When a user logins and does not have a matching user account in the local database, this will create a new user.  This is to be used in conjunction with `Default Groups`

> [!WARNING]
> It is recommended to keep this disabled. Your firewall isn't a service that should readily accept new users.

### Default Groups
When a new user is created, these groups will be assigned to them.

### Icon Url
An optional URL that will be proxied for the login button. You can access it at `/api/oidc/auth/icon?provider=<name>`

### Custom Button 
When provided, the button will be replaced with the custom one. 
There are several templates available:
- `%name%` Name of the provider 
- `%url%` URL that will start the auth flow
- `%icon%` The proxied icon image (useful to avoid CORS).

As an example, here is one that makes a nice big icon next to the login button
```html
<a href="%url%" class="btn btn-primary"><img src="%icon%" style="height: 2em"> Login with %name%</a> 
<style>.login-sso-link-container { display: flex; justify-content: end; margin-top: 15px; margin-right: 9px; }</style>
```

| Before | After |
|--------|-------|
| ![old login](https://i.lu.je/2025/firefox_laeaoIMkWI.png) | ![new login](https://i.lu.je/2025/firefox_q6dNnOaA8b.png) |

### Redirect URI
Fixed callback URL registered at the provider, e.g. `https://fw.example.com/api/oidc/auth/callback`. When empty the URL is derived from the request `Host` header, which is not recommended.

### Allowed tenant ID
Microsoft Entra ID only. Tokens whose `tid` claim differs from this value are rejected.

### Query UserInfo endpoint
Merges claims from the UserInfo endpoint into the ID token claims (ID token claims win). Keep disabled for Entra ID.

### Match users by email
Also matches local users by the `email` claim. Disabled by default because many providers (Entra ID included) do not guarantee a verified, immutable email.

### Group claim / Group mapping
`Group claim` names the claim holding roles or groups (`roles` by default). `Group mapping` holds one `claimValue=localGroup` per line:
```
OPNsense.Admin=admins
OPNsense.ReadOnly=readonly
```

### Synchronize groups
On every login the user is added to the mapped local groups present in the token and removed from mapped groups that are not. Groups that do not appear in the mapping are never touched.

### Require mapped group
Denies the login when none of the claim values is present in the mapping.

## Mapping
Users are matched by the configured `Username claim` taken from the **verified ID token** (and by `email` only when *Match users by email* is enabled).
New users (only with *Automatic user creation*) receive the `Default groups` plus the mapped groups.

Every login, denial and group change is written to the audit log (*System → Log Files → Audit*).

## Provider Setup
### All Providers
| Property | Value |
|----------|-------|
| Callback | `https://<ip of opnsense>/api/oidc/auth/callback` |

### PocketID
provider:
| Property | Value |
|----------|-------|
| Public Client | false |
| PKCE | false |
| Requires Re-Authentication| false |

client (opnsense):
| Setting | Value | 
|---------|-------|
| Username claim | `preferred_username` |

### Microsoft Entra ID
**App registration** (*Entra admin center → App registrations → New registration*):
| Property | Value |
|----------|-------|
| Supported account types | Single tenant |
| Redirect URI (Web) | `https://<fqdn of opnsense>/api/oidc/auth/callback` |
| Certificates & secrets | New client secret (store it in a vault, note the expiry) |
| App roles | `OPNsense.Admin`, `OPNsense.ReadOnly` (allowed member types: Users/Groups) |
| Token configuration | optional claim `email` (ID token) |

**Enterprise application** (same name): *Properties → Assignment required = Yes*, then assign users or groups to the app roles under *Users and groups*. Protect it with a Conditional Access policy requiring MFA.

> App roles are emitted in the `roles` claim of the ID token and avoid the groups overage limit (200 groups) of the `groups` claim.

client (opnsense):
| Setting | Value |
|---------|-------|
| Provider URL | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| Username claim | `preferred_username` (UPN) |
| Scopes | `openid,profile,email` |
| Redirect URI | `https://<fqdn of opnsense>/api/oidc/auth/callback` |
| Allowed tenant ID | `<tenant-id>` |
| Query UserInfo endpoint | disabled |
| Group claim | `roles` |
| Group mapping | `OPNsense.Admin=admins` |
| Synchronize groups | enabled |
| Require mapped group | enabled |

Create the local users beforehand with the UPN as username (or enable *Automatic user creation*), and keep the `Local Database` as a fallback authentication server with a break-glass `root` account.
The firewall itself needs outbound HTTPS to `login.microsoftonline.com`.

### Authentik
WIP

# Development
## VScode
To get VSCode to behave correctly with the OPNSense PHP, we will need to tell the language server where to find the classes we use.
I use [Intelephense](https://intelephense.com/) for work, and this is easy to configure with the `includePaths` setting. 

There are several parts we need:
1. [opnsense/core](https://github.com/opnsense/core)
   - This handles all the core functionality with OPNSense
2. [phalcon/ide-stubs](https://github.com/phalcon/ide-stubs)
   - OPNSense uses the [Phalcon](https://docs.phalcon.io/3.4/introduction/) framework, and this is a stubs library specifically for this use case. 

Once these are cloned into a repository, you can configure Intelephense to use them:
```json
{
    "intelephense.environment.includePaths": [
        "D:\\projects\\opnsense\\core\\src\\opnsense\\mvc",
        "D:\\projects\\opnsense\\core\\src\\etc\\inc",
        "D:\\projects\\opnsense\\core\\src\\www",
        "D:\\projects\\opnsense\\ide-stubs\\src"
    ],
    "explorer.compactFolders": false,
    "files.associations": {
        "*.inc": "php",
    }
}
```

## Setup on OPNSense
Here are the steps i have gotten to work with setup.

1. Clone [opnsense/plugins](https://github.com/opnsense/plugins) to `/usr/plugins`
2. Clone [opnsense/tools](https://github.com/opnsense/tools) to `/usr/tools`
3. `cd /usr/tools` and `make update`
4. `make plugins` (this might not be required. This will take a long time and tends to crash at libpam. I abort at this time )
5. Clone your project to `~/project-name`
6. Copy the project's content to `/usr/plugins/devel/project-name`
7. Build with `cd /usr/plugins/devel/project-name && make package`
8. Install `pkg add /usr/plugins/devel/project-name/work/pkg/*.pkg`
