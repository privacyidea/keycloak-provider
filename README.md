# privacyIDEA provider for Keycloak

This provider allows you to use privacyIDEA's 2FA with Keycloak.  
We added a detailed how-to on our [blog](https://community.privacyidea.org/t/how-to-use-keycloak-with-privacyidea/1132).

## Download

* Check our latest [releases](https://github.com/privacyidea/keycloak-provider/releases).
* Download the PrivacyIDEA-Provider.jar for your keycloak version.

## Installation
**Make sure to pick the correct jar for your keycloak version from the [releases page](https://github.com/privacyidea/keycloak-provider/releases)!**

#### Keycloak >= 17
* Keycloak has to be shut down
* Move the jar file into the `providers` directory
* Go to `bin` and run `kc.sh build` (or the batch file on windows)
* Start keycloak again

#### Keycloak <= 16
* Move the packed jar file into your deployment directory `standalone/deployment`.  
* Optional: Move the template privacyIDEA.ftl to `themes/base/login`. 
NOTE: For releases from version 0.6 onward, the template will be deployed automatically, so this step can be skipped.

Now you can enable the execution for your auth flow.  
If you set the execution as 'required', every user needs to login with a second factor.

## Configuration

The different configuration parameters that are available on the configuration page of the execution are explained in the following table:

| Configuration              | Explanation                                                                                                                                                                                                  |
|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| privacyIDEA URL            | The URL of your privacyIDEA server, which must be reachable from the keycloak server                                                                                                                         |
| Realm                      | This realm will be appended to all requests to privacyIDEA. Leave empty to use the privacyIDEA default realm                                                                                                 |
| Verify SSL                 | You can choose if Keycloak should verify the ssl certificate from privacyIDEA. Please do not uncheck this in a productive environment!                                                                       |
| Preferred Login Token Type | Select the token type for which the UI should be first shown. This only matters if such token was triggered before. The UI defaults to OTP mode.                                                             |
| Enable sending password    | Enable if the password that was used to authenticate with keycloak in the first step should be sent to privacyIDEA to trigger challenges. Mutually exclusive to trigger challenge                            |
| Enable trigger challenge   | Enable if challenges should be triggered beforehand using the provided service account. This is mutually exclusive to sending the password and takes precedence.                                             |
| Service account            | The username of the service account to trigger challenges or enroll tokens. Please make sure, that the service account has the correct rights.                                                               |
| Service account password   | The password of your service account                                                                                                                                                                         |
| Service account realm      | Specify a separate realm for the service account if needed. If the service account is in the same realm as the users, it is sufficient to specify the realm in the config parameter above.                   |
| Included groups            | Keycload groups that should be included to 2FA.  If one group will be added to both (included and excluded), excluding for this group will be ignored. Multiple groups can be specified, separated with ','. |
| Excluded groups            | Keycloak groups that should be excluded from 2FA. Multiple groups can be specified, separated with ','.                                                                                                      |
| Forward headers            | Set the headers which should be forwarded to privacyIDEA. If the header does not exist or has no value, it will be ignored. The headers names should be separated with ','.                                  |
| Enable token enrollment    | If the current user does not have a token yet, it can be enrolled. The service account has to be set up. **Starting in privacyIDEA server version 3.8, token enrollment can be done via challenge-response and centrally managed in the server. That is the preferred way of token enrollment while logging in. This feature is therefore deprecated and will be removed in a future version.**                                                                                               |
| Enrollment token type      | Select the token type for the token enrollment                                                                                                                                                               |
| Poll in browser            | Enable this to do the polling for accepted push requests in the user's browser. When enabled, the login page does not refresh when checking for successful push authentication. CORS settings for privacyidea can be adjusted in `etc/apache2/sites-available/privacyidea.conf`.                             |
| URL for poll in browser    | Optional. If poll in browser should use a deviating URL, set it here. Otherwise, the general URL will be used.                                                                                               |
| Push refresh interval      | Choose your custom interval in seconds to check if the push token is confirmed. This can be a comma separated list, if you want to change the interval                                                       |
| Enable logging             | Enable this to have the privacyIDEA Keycloak provider write log messages to the keycloak log file.                                                                                                           |

## Manual build with source code
* First, the client submodule has to be build using maven: ``mvn clean install`` in ``java-client``.
* Then build with ``mvn clean install`` in the provider directory and go on with **Installation**.
