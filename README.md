# Keycloak privacyIDEA provider

This provider allows you to use privacyIDEA's 2FA with Keycloak.

## Download

* Check our latest [releases](https://github.com/privacyidea/keycloak-provider/releases)
* Download the assets privacyIDEA.jar and privacyIDEA.ftl

## Installation

* Move the packed jar file into your deployment directory.  
* Copy the template privacyIDEA.ftl to `themes/base/login`.

Now you can enable the execution for your auth flow.  
Edit the privacyIDEA url and realms in the configuration  
If you set the execution as 'required', every user needs to login with a second factor.

## Manual build with source code

You can also build the provider yourself.  
***Notice:** This is not a stable release. Do not use it in a productive environment.*

* We used the [demo server](https://www.keycloak.org/archive/downloads-4.3.0.html) to build our plugin.
* Clone this repo to `keycloak-demo-4.3.0.Final/examples/providers`
* Build this provider with `mvn clean install wildfly:deploy`
* Pack the content of `target/classes` to privacyidea.jar

Go on with **Installation**.
