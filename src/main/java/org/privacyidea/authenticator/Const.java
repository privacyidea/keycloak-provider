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
    // User-Agent used for requests that belong to an EntraID (openid) external-authentication flow.
    static final String ENTRAID_USER_AGENT = "entraid-via-keycloak";

    static final String TRUE = "true";

    static final String HEADER_ACCEPT_LANGUAGE = "accept-language";
    // Will be used if no intervals are specified
    static final List<Integer> POLLING_INTERVALS = Arrays.asList(4, 3, 2);

    static final String FORM_FILE_NAME = "privacyIDEA.ftl";
    static final String FORM_OTP = "otp";

    static final String NOTE_OTP_TRANSACTION_ID = "pi_otp_transaction_id";
    static final String NOTE_WEBAUTHN_TRANSACTION_ID = "pi_webauthn_transaction_id";
    static final String NOTE_PUSH_TRANSACTION_ID = "pi_push_transaction_id";
    static final String NOTE_PASSKEY_TRANSACTION_ID = "pi_passkey_transaction_id";
    static final String NOTE_COUNTER = "authCounter";
    static final String NOTE_PASSKEY_REGISTRATION_SERIAL = "passkey_registration_serial";
    static final String NOTE_PREVIOUS_RESPONSE = "pi_previous_response";
    // Set when the current authentication originates from an EntraID (openid) request, so all privacyIDEA
    // requests in this flow use the EntraID User-Agent.
    static final String NOTE_ENTRAID_FLOW = "pi_entraid_flow";

    // OpenID Connect constants
    static final String OPENID_PARAM_SCOPE = "scope";
    static final String OPENID_VALUE = "openid";
    static final String OPENID_PARAM_ID_TOKEN_HINT = "id_token_hint";
    static final String OPENID_CLAIM_PREFERRED_USERNAME = "preferred_username";

    // Error Messages
    static final String MSG_INVALID_CREDENTIALS = "Invalid Credentials!";
    static final String MSG_USERNAME_REQUIRED = "Username is required!";
    static final String MSG_USER_NOT_FOUND = "User not found!";
    static final String MSG_PASSKEY_AUTH_FAILED = "passkey_authentication_failed";
    static final String MSG_PUSH_NOT_VERIFIED = "push_auth_not_verified";
    static final String MSG_AUTH_FAILED = "Authentication failed.";
    static final String MSG_PUSH_FAILED = "Push authentication failed. Please use a different token or restart the login.";

    // Changing the config value names will reset the current config
    static final String CONFIG_PUSH_INTERVAL = "pipushtokeninterval";
    static final String CONFIG_EXCLUDED_GROUPS = "piexcludegroups";
    static final String CONFIG_INCLUDED_GROUPS = "piincludegroups";
    static final String CONFIG_CHECK_INHERITED_GROUPS = "piCheckInheritedGroups";
    static final String CONFIG_FORWARDED_HEADERS = "piforwardedheaders";
    static final String CONFIG_FORWARD_CLIENT_IP = "piforwardclientip";
    static final String CONFIG_POLL_IN_BROWSER = "pipollinbrowser";
    static final String CONFIG_POLL_IN_BROWSER_URL = "pipollinbrowserurl";
    static final String CONFIG_SEND_PASSWORD = "pisendpassword";
    static final String CONFIG_TRIGGER_CHALLENGE = "pidotriggerchallenge";
    static final String CONFIG_SEND_STATIC_PASS = "pisendstaticpass";
    static final String CONFIG_PASSKEY_ONLY = "pipasskeyonly";
    static final String CONFIG_OTP_LENGTH = "piotplength";
    static final String CONFIG_SERVICE_PASS = "piservicepass";
    static final String CONFIG_SERVICE_ACCOUNT = "piserviceaccount";
    static final String CONFIG_SERVICE_REALM = "piservicerealm";
    static final String CONFIG_STATIC_PASS = "pistaticpass";
    static final String CONFIG_VERIFY_SSL = "piverifyssl";
    static final String CONFIG_REALM = "pirealm";
    static final String CONFIG_SERVER = "piserver";
    static final String CONFIG_ENABLE_LOG = "pidolog";
    static final String CONFIG_CUSTOM_HEADERS = "picustomheaders";
    static final String CONFIG_HTTP_TIMEOUT_MS = "pihttptimeoutms";
    static final String CONFIG_DISABLE_PASSWORD_CHECK = "pidisablepasswordcheck";
    static final String CONFIG_DISABLE_PASSKEY_LOGIN = "pidisablepasskeylogin";
    static final String CONFIG_OPENID_SEARCH_ATTRIBUTE = "piOpenIdSearchAttribute";
    static final String CONFIG_ENABLE_OPENID_SEARCH_BY_ATTRIBUTE = "piEnableOpenIdSearch";
    static final String CONFIG_ENTRAID_USER_AGENT = "piEntraIdSeparateUserAgent";
}