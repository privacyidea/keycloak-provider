[![Actions Status](https://github.com/privacyidea/keycloak-provider/workflows/Java%20CI/badge.svg)](https://github.com/privacyidea/keycloak-provider/actions)

# Keycloak privacyIDEA provider

This provider allows you to use privacyIDEA's 2FA with Keycloak.  
We added a detailed how to in our [blog](https://community.privacyidea.org/t/how-to-use-keycloak-with-privacyidea/1132).  
In this blog entry, you can find an example with Keycloak, privacyIDEA and Drupal.

## Download

* Check our latest [releases](https://github.com/privacyidea/keycloak-provider/releases)
* Download the assets privacyIDEA.jar and privacyIDEA.ftl

## Installation

* Move the packed jar file into your deployment directory `standalone/deployment`.  
* Move the template privacyIDEA.ftl to `themes/base/login`.

Now you can enable the execution for your auth flow.  
If you set the execution as 'required', every user needs to login with a second factor.

## org.privacyidea.org.privacyidea.authenticator.Configuration

You can find different preferences in your configuration, which are explained below.

| org.privacyidea.org.privacyidea.authenticator.Configuration | Explanation |
| ----- | ----- |
| URL | The URL of your privacyIDEA server, which must be reachable from the keycloak server |
| Realm | This is the realm, where the users are located in. Leave empty to use the privacyIDEA default realm|
| Verify SSL | You can choose if Keycloak should verify the ssl certificate from privacyIDEA. Please do not uncheck this in a productive environment! |
| Enable trigger challenge | Select if trigger challenge is enabled |
| Service account | The username of your service account to trigger challenges, enroll tokens or check if push tokens are confirmed. Please make sure, that the service account has the correct rights. |
| Service account password | The password of your service account |
| Exclude groups | You can exclude groups from 2FA |
| Enable token enrollment | If the current user does not have a token yet, it can be enrolled. The service account has to be set up |
| Token type | Select the token type for the token enrollment |
| Refresh interval for push tokens | Choose your custom interval in seconds to check if the push token is confirmed. This can be a comma separated list, if you want to change the interval |

## Manual build with source code

* If the wildfly server is running, the authenticator can directly be deployed with
``mvn clean install wildfly:deploy`` and only the template has to be copied.

* Otherwise build with ``mvn clean install`` and go on with **Installation**
