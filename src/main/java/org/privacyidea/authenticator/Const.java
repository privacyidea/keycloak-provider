/*
 * Copyright 2023 NetKnights GmbH - nils.behlen@netknights.it
 * lukas.matusiewicz@netknights.it
 * - Modified
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea.authenticator;

import java.util.Arrays;
import java.util.List;

final class Const
{
    private Const()
    {
    }

    static final String PROVIDER_ID = "privacyidea-authenticator";
    static final String PLUGIN_USER_AGENT = "privacyIDEA-Keycloak";

    static final String DEFAULT_PUSH_MESSAGE_EN = "Please confirm the authentication on your mobile device!";
    static final String DEFAULT_PUSH_MESSAGE_DE = "Bitte bestätigen Sie die Authentifizierung auf ihrem Smartphone!";

    static final String DEFAULT_OTP_MESSAGE_EN = "Please enter your One-Time-Password!";
    static final String DEFAULT_OTP_MESSAGE_DE = "Bitte geben Sie ihr Einmalpasswort ein!";

    static final String TRUE = "true";

    static final String HEADER_ACCEPT_LANGUAGE = "accept-language";
    // Will be used if single value from config cannot be parsed
    static final int DEFAULT_POLLING_INTERVAL = 2;
    // Will be used if no intervals are specified
    static final List<Integer> DEFAULT_POLLING_ARRAY = Arrays.asList(4, 2, 2, 2, 3);

    static final String FORM_POLL_INTERVAL = "pollingInterval";
    static final String FORM_TOKEN_ENROLLMENT_QR = "tokenEnrollmentQR";
    static final String FORM_MODE = "mode";
    static final String FORM_IMAGE_PUSH = "pushImage";
    static final String FORM_IMAGE_OTP = "otpImage";
    static final String FORM_IMAGE_WEBAUTHN = "webauthnImage";
    static final String FORM_POLL_IN_BROWSER = "pollInBrowser";
    static final String FORM_POLL_IN_BROWSER_FAILED = "pollInBrowserFailed";
    static final String FORM_ERROR_MESSAGE = "errorMsg";
    static final String FORM_TRANSACTION_ID = "transactionID";
    static final String FORM_PI_SERVER_URL = "piServerUrl";
    static final String FORM_PUSH_AVAILABLE = "push_available";
    static final String FORM_OTP_AVAILABLE = "otp_available";
    static final String FORM_PUSH_MESSAGE = "pushMessage";
    static final String FORM_OTP_MESSAGE = "otpMessage";
    static final String FORM_FILE_NAME = "privacyIDEA.ftl";
    static final String FORM_MODE_CHANGED = "modeChanged";
    static final String FORM_OTP = "otp";
    static final String FORM_UI_LANGUAGE = "uilanguage";
    static final String FORM_ERROR = "hasError";

    // Webauthn form fields
    static final String FORM_WEBAUTHN_SIGN_REQUEST = "webauthnsignrequest";
    static final String FORM_WEBAUTHN_SIGN_RESPONSE = "webauthnsignresponse";
    static final String FORM_WEBAUTHN_ORIGIN = "origin";

    // U2F form fields
    static final String FORM_U2F_SIGN_REQUEST = "u2fsignrequest";
    static final String FORM_U2F_SIGN_RESPONSE = "u2fsignresponse";

    static final String AUTH_NOTE_TRANSACTION_ID = "transaction_id";
    static final String AUTH_NOTE_AUTH_COUNTER = "authCounter";
    static final String AUTH_NOTE_ACCEPT_LANGUAGE = "authLanguage";

    // Changing the config value names will reset the current config
    static final String CONFIG_PUSH_INTERVAL = "pipushtokeninterval";
    static final String CONFIG_EXCLUDED_GROUPS = "piexcludegroups";
    static final String CONFIG_INCLUDED_GROUPS = "piincludegroups";
    static final String CONFIG_FORWARDED_HEADERS = "piforwardedheaders";
    static final String CONFIG_ENROLL_TOKEN_TYPE = "pienrolltokentype";
    static final String CONFIG_ENROLL_TOKEN = "pienrolltoken";
    static final String CONFIG_SEND_PASSWORD = "pisendpassword";
    static final String CONFIG_POLL_IN_BROWSER = "pipollinbrowser";
    static final String CONFIG_SERVICE_PASS = "piservicepass";
    static final String CONFIG_SERVICE_ACCOUNT = "piserviceaccount";
    static final String CONFIG_SERVICE_REALM = "piservicerealm";
    static final String CONFIG_TRIGGER_CHALLENGE = "pidotriggerchallenge";
    static final String CONFIG_VERIFY_SSL = "piverifyssl";
    static final String CONFIG_REALM = "pirealm";
    static final String CONFIG_SERVER = "piserver";
    static final String CONFIG_ENABLE_LOG = "pidolog";
    static final String CONFIG_PREF_TOKEN_TYPE = "preftokentype";
}