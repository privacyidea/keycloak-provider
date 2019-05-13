# Keycloak privacyIDEA provider

This provider allows you to use privacyIDEA's 2FA with Keycloak.

## Download

* Check our latest [releases](https://github.com/privacyidea/keycloak-provider/releases)
* Download the assets privacyIDEA.jar and privacyIDEA.ftl

## Installation

* Move the packed jar file into your deployment directory.  
* Copy the template privacyIDEA.ftl to `themes/base/login`.

Now you can enable the execution for your auth flow.  
If you set the execution as 'required', every user needs to login with a second factor.

## Configuration

You can find different preferences in your configuration, which are explained below.

| Configuration | Explanation |
| ----- | ----- |
| URL | The URL to your privacyIDEA server, which must be reachable from the keycloak server |
| Realm | This is the realm, where the users are located in. Leave empty for default |
| Verify SSL | You can choose if Keycloak should verify the ssl certificate from privacyIDEA. Please do not uncheck this in a productive environment! |
| Enable trigger challenge | Select if trigger challenge is enabled |
| Service account | The username for your service account to trigger challenges, enroll tokens or check if push tokens are confirmed. Please make sure, that the service account needs to have the correct rights. |
| Service account password | The password for your service account |
| Exclude groups | You can exclude groups from 2FA |
| Enable token enrollment | If the current user does not have a token yet, it can be enrolled. The service account has to be set up |
| Token type | Select the token type for the token enrollment |
| Refresh interval for push tokens | Choose your custom interval in seconds to check if the push token is confirmed. This can be a comma separated list, if you want to change the interval |

## Manual build with source code

You can also build the provider yourself.  
***Notice:** This is not a stable release. Do not use it in a productive environment.*

* We used the [demo server](https://www.keycloak.org/archive/downloads-4.3.0.html) to build our plugin.
* Clone this repo to `keycloak-demo-4.3.0.Final/examples/providers`
* Build this provider with `mvn clean install wildfly:deploy`
* Pack the content of `target/classes` to privacyidea.jar

Go on with **Installation**.