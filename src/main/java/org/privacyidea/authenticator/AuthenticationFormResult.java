/*
 * Copyright 2023 NetKnights GmbH - nils.behlen@netknights.it
 * lukas.matusiewicz@netknights.it
 * - Modified
 * <p>
 * SPDX-License-Identifier: Apache-2.0
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

import com.google.gson.Gson;

/**
 * This class holds the data that gets passed from js (/freemarker) back to java. It is assembled in js, serialized to json
 * and passed to java.
 */
public class AuthenticationFormResult
{
    public boolean authenticationResetRequested = false;
    public boolean passkeyLoginRequested = false;
    public boolean passkeyLoginCancelled = false;
    public boolean modeChanged = false;
    public Mode newMode = null;
    // The SignResponse is differentiated for passkey and webauthn because passkey is expected to return the username, so the order of
    // their use is inverted.
    public String webAuthnSignResponse = null;
    public String passkeySignResponse = null;
    public String origin = null;
    public String passkeyRegistrationResponse = null;

    public String toString() {
        return new Gson().toJson(this);
    }

    public static AuthenticationFormResult fromJson(String json) {
        return new Gson().fromJson(json, AuthenticationFormResult.class);
    }
}