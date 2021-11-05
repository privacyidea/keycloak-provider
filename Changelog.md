# Changelog

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
