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

    static final String TRUE = "true";

    static final String HEADER_ACCEPT_LANGUAGE = "accept-language";
    // Will be used if single value from config cannot be parsed
    static final int DEFAULT_POLLING_INTERVAL = 2;
    // Will be used if no intervals are specified
    static final List<Integer> DEFAULT_POLLING_ARRAY = Arrays.asList(4, 2, 2, 2, 3);

    static final String FORM_FILE_NAME = "privacyIDEA.ftl";
    static final String FORM_OTP = "otp";

    static final String NOTE_TRANSACTION_ID = "transaction_id";
    static final String NOTE_PASSKEY_TRANSACTION_ID = "passkey_transaction_id";
    static final String NOTE_COUNTER = "authCounter";
    static final String NOTE_PASSKEY_REGISTRATION_SERIAL = "passkey_registration_serial";

    // Changing the config value names will reset the current config
    static final String CONFIG_PUSH_INTERVAL = "pipushtokeninterval";
    static final String CONFIG_EXCLUDED_GROUPS = "piexcludegroups";
    static final String CONFIG_INCLUDED_GROUPS = "piincludegroups";
    static final String CONFIG_FORWARDED_HEADERS = "piforwardedheaders";
    static final String CONFIG_FORWARD_CLIENT_IP = "piforwardclientip";
    static final String CONFIG_DEFAULT_MESSAGE = "pidefaultmessage";
    static final String CONFIG_POLL_IN_BROWSER = "pipollinbrowser";
    static final String CONFIG_POLL_IN_BROWSER_URL = "pipollinbrowserurl";
    static final String CONFIG_SEND_PASSWORD = "pisendpassword";
    static final String CONFIG_TRIGGER_CHALLENGE = "pidotriggerchallenge";
    static final String CONFIG_SEND_STATIC_PASS = "pisendstaticpass";
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
}