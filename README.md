# PrivacyIDEA Provider for Keycloak

[![Build](https://github.com/privacyidea/keycloak-provider/actions/workflows/build.yml/badge.svg)](https://github.com/privacyidea/keycloak-provider/actions/workflows/build.yml)
[![CodeQL](https://github.com/privacyidea/keycloak-provider/actions/workflows/codeql.yml/badge.svg)](https://github.com/privacyidea/keycloak-provider/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/privacyidea/keycloak-provider/badge)](https://scorecard.dev/viewer/?uri=github.com/privacyidea/keycloak-provider)

This provider allows you to use privacyIDEA's MFA with Keycloak.  
We added a detailed how-to on our [blog](https://community.privacyidea.org/t/how-to-use-keycloak-with-privacyidea/1132).
With version 1.5.0 of this provider, the username and password step of keycloak is not required any more, this provider will handle it.
If you still want to use it, this provider will use the username and password provided.
Another option that is now possible is to have the check for the second factor first with this provider and then add a step with the keycloak password form after this.
## Download

* Check our latest [releases](https://github.com/privacyidea/keycloak-provider/releases).

## Installation

**Make sure to pick the correct jar for your keycloak version from
the [releases page](https://github.com/privacyidea/keycloak-provider/releases) if there are multiple options!**

* Keycloak has to be shut down.
* Move the jar file into the `providers` directory.
* Go to `bin` and run `kc.sh build` (or the batch file on windows). Or just start keycloak, depending on the version.
* Start keycloak again.

Now you can enable the execution for your auth flow.  
If you set the execution as 'required', every user needs to log in with a second factor.

## Configuration

The different configuration parameters that are available on the configuration page of the execution are explained in
the following table:

| Configuration | Explanation |
|---|---|
| PrivacyIDEA URL | The URL of your privacyIDEA server, which must be reachable from the keycloak server. |
| Realm | This realm will be appended to all requests to privacyIDEA. Leave empty to use the privacyIDEA default realm. |
| Verify SSL | You can choose if Keycloak should verify the SSL certificate from privacyIDEA. Please do not uncheck this in a productive environment! |
| Enable Trigger Challenge | Enable if challenges should be triggered beforehand using the provided service account. This is mutually exclusive to sending the password and takes precedence. |
| Service Account | The username of the service account to trigger challenges or enroll tokens. Please make sure, that the service account has the correct rights. |
| Service Account Password | The password of your service account. |
| Service Account Realm | Specify a separate realm for the service account if needed. If the service account is in the same realm as the users, it is sufficient to specify the realm in the config parameter above. |
| Send Password | Enable if the password that was used to authenticate with keycloak in the first step should be sent to privacyIDEA prior to the authentication. Can be used to trigger challenges. Mutually exclusive to trigger challenge. |
| Send Static Password | Enable if the configured *static password* should be sent to privacyIDEA prior to the authentication. Can be used to trigger challenges. If trigger challenge or send password is enabled, this will be ignored. |
| Static Password | The static password for *send static password*. Can also be empty to send an empty password. |
| Disable Password Check | Since v1.5.0, this provider can verify the user password. This can be disabled, so that you either have a passwordless login, or you can add the keycloak password step after this provider. |
| Disable Passkey Login | Disable the "Sign in with Passkey" button, effectively disabling passkey authentication. NOTE: If this is enabled, the 'Passkey Only' option will be ignored. |
| Enable OpenID User Search by Attribute | For OpenID requests (e.g. the EntraID external-authentication method), the Keycloak user is normally resolved by matching the `preferred_username` claim against the username. Enable this to first look the user up by a custom user attribute (*OpenID Search Attribute*) instead. If no user matches that attribute, the lookup falls back to the username. |
| OpenID Search Attribute | The Keycloak user attribute matched against the `preferred_username` claim of the incoming OpenID request. Only used when *Enable OpenID User Search by Attribute* is on. Example: an attribute holding the EntraID identifier the user is synchronized with. |
| Enable Separate User-Agent for EntraID | When enabled, requests that originate from an EntraID (openid) external-authentication flow use the User-Agent `entraid-via-keycloak/<version>` instead of the default plugin User-Agent. |
| Disable EntraID id_token_hint Verification | By default, when an OpenID request from EntraID carries an `id_token_hint`, its signature is verified against Microsoft's published keys (issuer and, if set, audience are checked; expiry is not, because EntraID issues the hint already expired). If the keys can't be fetched or verification fails, the request is rejected. Enable this to skip verification and trust the `id_token_hint` as-is. Only affects requests whose issuer is an EntraID/Microsoft host. |
| EntraID Audience (Application/Client ID) | Optional. The application (client) ID that EntraID was configured with for this external authentication method. When set, it's checked against the `aud` claim of the `id_token_hint` during verification (recommended by Microsoft). Leave empty to skip the audience check; signature and issuer are still verified. |
| Passkey Only | Run the provider in Passkey Only mode: authentication is only possible with passkeys, and PUSH, OTP and other tokens are not offered. Requires that users have passkeys enrolled in privacyIDEA. Ignored if 'Disable Passkey Login' is enabled. |
| Included groups | Keycloak groups that should be included to 2FA. Multiple groups can be specified, separated with ','. NOTE: If both included and excluded are configured, the excluded setting will be ignored! |
| Excluded groups | Keycloak groups that should be excluded from 2FA. Multiple groups can be specified, separated with ','. |
| Check Inherited Groups | When matching the included/excluded groups, also consider the parent groups of the user's groups by walking up the group hierarchy. Only works when the hierarchy exists in Keycloak (native nested groups, or LDAP groups imported with "Preserve Group Inheritance"); flat-imported LDAP groups have no parents to check. |
| Auto-Submit OTP Length | If you want to turn on the form-auto-submit function after x number of characters are entered into the OTP input field, set the expected OTP length. |
| Forward Client IP | Enable this to add the parameter `clientip` to every request, if the ip of the client is available. |
| HTTP Timeout (ms) | Set a custom value for the HTTP timeout in milliseconds. |
| Headers to Forward | Set the headers which should be forwarded to privacyIDEA. If the header does not exist or has no value, it will be ignored. The header names should be separated with ','. |
| Custom Headers | Set the custom headers which will be sent with every request. Each entry needs to have the format key=value. Entries that do not have this format will be ignored. Do not use well known headers like 'Authorization' and do not use '##'. |
| Poll in Browser | Enable this to do the polling for accepted push requests in the user's browser. When enabled, the login page does not refresh when checking for successful push authentication. CORS settings for privacyidea can be adjusted in `etc/apache2/sites-available/privacyidea.conf`. |
| URL for Poll in Browser | Optional. If poll in browser should use a deviating URL, set it here. Otherwise, the general URL will be used. |
| Enable Logging | Enable this to have the privacyIDEA Keycloak provider write log messages to the keycloak log file. |

### Changing texts

If you want to change any of the default texts for any localization, you can directly edit the corresponding file in the
`resources\theme-resources\messsages` directory.

## Manual build with source code

* First, the client submodule has to be build using maven: ``mvn clean install`` in ``java-client``.
* Then build with ``mvn clean install`` in the provider directory and go on with **Installation**.

## Usernameless Authentication

If you decide to use a usernameless authentication, the group membership can not be evaluated and the excluded and included group setting will have no effect.
If you had users excluded previously, make sure they have a passkey token before enabling this feature.
