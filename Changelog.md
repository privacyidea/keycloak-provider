# Changelog

### v1.4.1 - 2024-03-05

* Fixed a bug that would cause empty error messages to appear in the log
* The threadpool allows core threads to time out, which will reduce the memory footprint of the provider 

### v1.4.0 - 2023-11-07

* Added `sendStaticPass` feature to send a static (or empty) password to trigger challenges
* Added automatic submit after X entered digits option

### v1.3.0 - 2023-08-11

* Added poll in browser setting. This moves the polling for successful push authentication to the browser of the user so that the site does not have to reload. (#133)
* Default OTP text is now customizable. (#137)

* Added compatibility for keycloak 22
* Removed listing as theme from keycloak settings

### v1.2.0 - 2023-01-25

* Added implementation of the preferred client mode (#121)
* Added implementation of a new feature: Token enrollment via challenge (#125)

### v1.1.0 - 2022-07-01

* Included groups setting to specify groups of keycloak users for which 2FA should be activated (#54). Check the [configuration documenation](https://github.com/privacyidea/keycloak-provider#configuration).
* It is now possible to configure the names of header that should be forwarded to privacyIDEA (#94)
* If a user has multiple WebAuthn token, all of them can be used to log in (#84)

* Fixed a bug where the provider would crash if privacyIDEA sent a response with missing fields (#105)

### v1.0.0 - 2021-11-06

* Support for different configurations in different keycloak realms
* U2F

### v0.6 - 2021-04-03

* WebAuthn support
* PIN change via challenge-response

### v0.5.1 - 2020-11-26

* Use java sdk for communication with privacyIDEA
* Added user-agent to http requests

### v0.5 - 2020-06-10

* Fixed a bug where overlapping logins could override the username in the login process

### v0.4 - 2020-04-24

* Changed configuration input type to match new version of keycloak
* Use /validate/polltransaction to check if push was confirmed

### v0.3 - 2019-10-22

* Reset error message when switching between OTP and push
* Catch parsing error for push intervals
* Remove duplicates for token messages

### v0.2 - 2019-05-22

* Add trigger challenge
* Add possibility to exclude keycloak's groups from 2FA
* Add token enrollment, if user does not have a token
* Add push tokens
* Add logging behaviour
* Add transaction id for validate/check

### v0.1 - 2019-04-11

* First version
* Supports basic OTP token