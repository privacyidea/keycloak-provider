# Keycloak privacyIDEA provider

This provider allows you to use privacyIDEA's 2FA with Keycloak.

## Installation

* After building this provider with `mvn clean install wildfly:deploy`
* Pack the content of `target/classes` to `privacyidea.jar`
* Move the packed jar file into your deployment directory.  
* Copy the template privacyIDEA.ftl to `themes/base/login`.

Now you can enable the execution for your auth flow.  
In the config file, edit the privacyIDEA URL and the realm.  
If you set the execution as 'required', every user needs to login with a second factor.
