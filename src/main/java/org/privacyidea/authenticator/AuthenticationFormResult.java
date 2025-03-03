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
    public String pollInBrowserError = null;
    public String origin = null;
    public String passkeyRegistrationResponse = null;

    public String toString() {
        return new Gson().toJson(this);
    }

    public static AuthenticationFormResult fromJson(String json) {
        return new Gson().fromJson(json, AuthenticationFormResult.class);
    }
}