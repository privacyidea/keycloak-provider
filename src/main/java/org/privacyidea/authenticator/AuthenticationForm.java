package org.privacyidea.authenticator;

import com.google.gson.Gson;
import org.keycloak.utils.StringUtil;

/**
 * This class holds the data that gets passed from java to freemarker/js.
 * For the way back from freemarker/js to java, AuthenticationFormResult is used.
 * Because freemarker can only read the values, this class contains only data that needs to be read.
 */
public class AuthenticationForm
{
    private Mode mode = Mode.OTP;
    private boolean otpAvailable = true;
    private String otpMessage = null;
    private boolean pushAvailable = false;
    private String pushMessage = null;
    private String webAuthnSignRequest = null;
    private String autoSubmitLength = null;
    private String transactionId = null;
    private String pollInBrowserURL = null;
    private int pollInterval = 2;
    private String errorMessage = null;
    private String pushImage = null;
    private String otpImage = null;
    private String webAuthnImage = null;
    private String enrollmentLink = null;
    private boolean challengesTriggered = false;
    // passkeyChallenge is separate from fido2SignRequest, because we need to remember if we are using passkey (=> we get the username
    // from privacyIDEA) or the regular webauthn that has been triggered for the user explicitly.
    private String passkeyRegistration = null;
    private String passkeyChallenge = null;

    public boolean isFirstStep()
    {
        return Mode.USERNAME.equals(mode) || Mode.USERNAMEPASSWORD.equals(mode);
    }

    public boolean isPollInBrowserAvailable()
    {
        return StringUtil.isNotBlank(pollInBrowserURL) && StringUtil.isNotBlank(transactionId);
    }

    public String getPushImage()
    {
        return pushImage;
    }

    public void setPushImage(String pushImage)
    {
        this.pushImage = pushImage;
    }

    public String getOtpImage()
    {
        return otpImage;
    }

    public void setOtpImage(String otpImage)
    {
        this.otpImage = otpImage;
    }

    public String getWebAuthnImage()
    {
        return webAuthnImage;
    }

    public void setWebAuthnImage(String webAuthnImage)
    {
        this.webAuthnImage = webAuthnImage;
    }

    public String getErrorMessage()
    {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage)
    {
        this.errorMessage = errorMessage;
    }

    public String getImage()
    {
        return image;
    }

    public void setImage(String image)
    {
        this.image = image;
    }

    private String image = null;

    public boolean isOtpAvailable()
    {
        return otpAvailable;
    }

    public void setOtpAvailable(boolean otpAvailable)
    {
        this.otpAvailable = otpAvailable;
    }

    public String getOtpMessage()
    {
        return otpMessage;
    }

    public void setOtpMessage(String otpMessage)
    {
        this.otpMessage = otpMessage;
    }

    public boolean isPushAvailable()
    {
        return pushAvailable;
    }

    public void setPushAvailable(boolean pushAvailable)
    {
        this.pushAvailable = pushAvailable;
    }

    public String getPushMessage()
    {
        return pushMessage;
    }

    public void setPushMessage(String pushMessage)
    {
        this.pushMessage = pushMessage;
    }

    public String getWebAuthnSignRequest()
    {
        return webAuthnSignRequest;
    }

    public void setWebAuthnSignRequest(String webAuthnSignRequest)
    {
        this.webAuthnSignRequest = webAuthnSignRequest;
    }

    public String getAutoSubmitLength()
    {
        return autoSubmitLength;
    }

    public void setAutoSubmitLength(String autoSubmitLength)
    {
        this.autoSubmitLength = autoSubmitLength;
    }

    public String getTransactionId()
    {
        return transactionId;
    }

    public void setTransactionId(String transactionId)
    {
        this.transactionId = transactionId;
    }

    public String getPollInBrowserURL()
    {
        return pollInBrowserURL;
    }

    public void setPollInBrowserURL(String pollInBrowserURL)
    {
        this.pollInBrowserURL = pollInBrowserURL;
    }

    public int getPollInterval()
    {
        return pollInterval;
    }

    public void setPollInterval(int pollInterval)
    {
        this.pollInterval = pollInterval;
    }

    public Mode getMode()
    {
        if (mode == null)
        {
            return Mode.OTP;
        }
        return mode;
    }

    public void setMode(Mode mode)
    {
        this.mode = mode;
    }

    public String toString()
    {
        return new Gson().toJson(this);
    }

    public static AuthenticationForm fromJson(String json)
    {
        return new Gson().fromJson(json, AuthenticationForm.class);
    }

    public boolean isChallengesTriggered()
    {
        return challengesTriggered;
    }

    public void setChallengesTriggered(boolean challengesTriggered)
    {
        this.challengesTriggered = challengesTriggered;
    }

    public String getPasskeyRegistration()
    {
        return passkeyRegistration;
    }

    public void setPasskeyRegistration(String passkeyRegistration)
    {
        this.passkeyRegistration = passkeyRegistration;
    }

    public String getPasskeyChallenge()
    {
        return passkeyChallenge;
    }

    public void setPasskeyChallenge(String passkeyChallenge)
    {
        this.passkeyChallenge = passkeyChallenge;
    }

    public String getEnrollmentLink()
    {
        return enrollmentLink;
    }

    public void setEnrollmentLink(String enrollmentLink)
    {
        this.enrollmentLink = enrollmentLink;
    }
}