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