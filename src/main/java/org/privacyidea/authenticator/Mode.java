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

import com.google.gson.annotations.SerializedName;

public enum Mode
{
    @SerializedName("username")
    USERNAME("username"),
    @SerializedName("password")
    PASSWORD("password"),
    @SerializedName("usernamepassword")
    USERNAMEPASSWORD("usernamepassword"),
    @SerializedName("otp")
    OTP("otp"),
    @SerializedName("passkey")
    PASSKEY("passkey"),
    @SerializedName("webauthn")
    WEBAUTHN("webauthn"),
    @SerializedName("push")
    PUSH("push"),
    @SerializedName("passkeyonly")
    PASSKEYONLY("passkeyonly");

    private final String mode;

    Mode(String mode)
    {
        this.mode = mode;
    }

    @Override
    public String toString()
    {
        return mode.toLowerCase();
    }
}