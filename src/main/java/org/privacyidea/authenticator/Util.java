package org.privacyidea.authenticator;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;
import org.privacyidea.Challenge;
import org.privacyidea.IPILogger;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;

import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;
import static org.privacyidea.authenticator.Const.HEADER_ACCEPT_LANGUAGE;
import static org.privacyidea.authenticator.Const.NOTE_OTP_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_PASSKEY_REGISTRATION_SERIAL;
import static org.privacyidea.authenticator.Const.NOTE_PASSKEY_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_PREVIOUS_RESPONSE;
import static org.privacyidea.authenticator.Const.NOTE_PUSH_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_WEBAUTHN_TRANSACTION_ID;

public class Util
{
    private final IPILogger logger;

    public Util(IPILogger logger)
    {
        this.logger = logger;
    }

    /**
     * Extract the headers that should be forwarded to privacyIDEA from the original request to keycloak. The header names
     * can be defined in the configuration of this provider. The accept-language header is included by default.
     * Also add the custom headers from the configuration if any are defined.
     *
     * @param context AuthenticationFlowContext
     * @param config  Configuration
     * @return Map of headers
     */
    Map<String, String> getHeaders(AuthenticationFlowContext context, Configuration config)
    {
        Map<String, String> headers = new LinkedHashMap<>();
        // Take all headers from config plus accept-language
        config.forwardedHeaders().add(HEADER_ACCEPT_LANGUAGE);

        for (String header : config.forwardedHeaders().stream().distinct().collect(Collectors.toList()))
        {
            List<String> headerValues = context.getSession().getContext().getRequestHeaders().getRequestHeaders().get(header);

            if (headerValues != null && !headerValues.isEmpty())
            {
                String temp = String.join(",", headerValues);
                headers.put(header, temp);
            }
            else
            {
                logger.log("No values for header " + header + " found.");
            }
        }
        headers.putAll(config.customHeaders());
        return headers;
    }

    /**
     * Check if the user is member of an included or excluded group. Included groups have precedence over excluded groups.
     * If user is null, return false (=MFA required).
     *
     * @param config Configuration
     * @param user   UserModel
     * @return true if no MFA is required, false if MFA is required
     */
    boolean checkMFAExcludedByGroup(Configuration config, UserModel user)
    {
        if (user == null || config == null)
        {
            return false;
        }
        if (!config.includedGroups().isEmpty())
        {
            return user.getGroupsStream().map(GroupModel::getName).noneMatch(config.includedGroups()::contains);
        }
        else if (!config.excludedGroups().isEmpty())
        {
            return user.getGroupsStream().map(GroupModel::getName).anyMatch(config.excludedGroups()::contains);
        }
        return false;
    }

    private AuthenticationForm challengesToForm(AuthenticationForm authForm, PIResponse response, Configuration config,
                                                AuthenticationFlowContext context)
    {
        if (response == null || response.multiChallenge == null || response.multiChallenge.isEmpty())
        {
            return authForm;
        }

        authForm.setChallengesTriggered(true);
        authForm.setEnrollViaMultichallengeOptional(response.isEnrollViaMultichallengeOptional);
        Mode mode = Mode.OTP;
        String newOtpMessage = response.otpMessage();
        // Images per challenge
        for (Challenge c : response.multiChallenge)
        {
            if ("poll".equals(c.getClientMode()))
            {
                String image = c.getImage();
                if (StringUtil.isNotBlank(image))
                {
                    authForm.setPushImage(c.getImage());
                    // TODO assume that if we have an image for a push token, it has to be enroll_via_multichallenge
                    authForm.setEnrollViaMultichallenge(true);
                    mode = Mode.PUSH;
                    authForm.setOtpAvailable(false);
                }
            }
            else if ("interactive".equals(c.getClientMode()))
            {
                authForm.setOtpImage(c.getImage());
            }
            else if ("webauthn".equals(c.getClientMode()))
            {
                authForm.setWebAuthnImage(c.getImage());
            }
        }

        // Poll in browser
        if (config.pollInBrowser() && response.pushAvailable())
        {
            authForm.setTransactionId(response.pushTransactionId());
            newOtpMessage = response.otpMessage() + ". " + response.pushMessage();
            String url = config.pollInBrowserUrl().isEmpty() ? config.serverURL() : config.pollInBrowserUrl();
            authForm.setPollInBrowserURL(url);
        }
        // Push
        if (response.pushAvailable())
        {
            authForm.setPushAvailable(true);
            authForm.setPushMessage(response.pushMessage());
        }
        // WebAuthn
        if (response.triggeredTokenTypes().contains(TOKEN_TYPE_WEBAUTHN))
        {
            authForm.setWebAuthnSignRequest(response.mergedSignRequest());
        }
        // Passkey Registration
        if (StringUtil.isNotBlank(response.passkeyRegistration))
        {
            authForm.setPasskeyRegistration(response.passkeyRegistration);
            context.getAuthenticationSession().setAuthNote(NOTE_PASSKEY_REGISTRATION_SERIAL, response.serial);
            context.getAuthenticationSession().setAuthNote(NOTE_PASSKEY_TRANSACTION_ID, response.transactionID);
        }
        // Preferred client mode
        if (StringUtil.isNotBlank(response.preferredClientMode))
        {
            try
            {
                mode = Mode.valueOf(response.preferredClientMode.toUpperCase());
            }
            catch (IllegalArgumentException e)
            {
                logger.error("Preferred client mode " + response.preferredClientMode + " is not valid, defaulting to OTP.");
            }
        }
        // Using poll in browser does not require push mode
        if (mode.equals(Mode.PUSH) && config.pollInBrowser() && !authForm.isEnrollViaMultichallenge())
        {
            mode = Mode.OTP;
        }

        // Set the transactionIds for the different modes
        if (StringUtil.isNotBlank(response.otpTransactionId()))
        {
            context.getAuthenticationSession().setAuthNote(NOTE_OTP_TRANSACTION_ID, response.otpTransactionId());
        }
        if (StringUtil.isNotBlank(response.pushTransactionId()))
        {
            context.getAuthenticationSession().setAuthNote(NOTE_PUSH_TRANSACTION_ID, response.pushTransactionId());
        }
        if (StringUtil.isNotBlank(response.webAuthnTransactionId))
        {
            context.getAuthenticationSession().setAuthNote(NOTE_WEBAUTHN_TRANSACTION_ID, response.webAuthnTransactionId);
        }
        authForm.setMode(mode);
        authForm.setOtpMessage(newOtpMessage);
        return authForm;
    }

    /**
     * Evaluate the response from privacyIDEA and set the form values accordingly. If there is a response, a new AuthenticationForm is created
     * and returned. Some values of the old form can be retained if they are not set to new values by the last response.
     * If there is no response, the old form is returned.
     *
     * @param response PIResponse
     * @param context  AuthenticationFlowContext
     * @param authForm AuthenticationForm from the previous step
     * @param config   Configuration
     * @return AuthenticationForm with new values or the old one if no response
     */
    AuthenticationForm evaluateResponse(PIResponse response, AuthenticationFlowContext context, AuthenticationForm authForm,
                                        Configuration config)
    {
        if (response != null)
        {
            Mode previousMode = authForm.getMode();
            authForm = new AuthenticationForm(config);
            authForm.setMode(previousMode);
            authForm.setEnrollmentLink(response.enrollmentLink);
            if (response.error != null)
            {
                authForm.setErrorMessage(response.error.message);
            }
            // New challenges, set the current response as previous response
            // Responses like "wrong otp" or "user not found" do not contain information that we need to remember.
            if (!response.multiChallenge.isEmpty())
            {
                authForm = challengesToForm(authForm, response, config, context);
                String p = response.toJSON();
                context.getAuthenticationSession().setAuthNote(NOTE_PREVIOUS_RESPONSE, p);
            }
            else if (!response.authenticationSuccessful())
            {
                // If the response is not successful, set the error message and restore the previous response to the authform
                String previousResponseString = context.getAuthenticationSession().getAuthNote(NOTE_PREVIOUS_RESPONSE);
                PIResponse previousResponse = PIResponse.fromJSON(previousResponseString);
                authForm = challengesToForm(authForm, previousResponse, config, context);
                authForm.setErrorMessage(response.message);
            }
        }
        return authForm;
    }

    Map<String, String> getAdditionalParamsFromContext(AuthenticationFlowContext context, Configuration config)
    {
        Map<String, String> additionalParams = new LinkedHashMap<>();
        if (config.forwardClientIP())
        {
            String clientIP = context.getConnection().getRemoteAddr();
            if (StringUtil.isBlank(clientIP))
            {
                logger.error("ClientIP is empty, cannot forward it to privacyIDEA.");
            }
            else
            {
                additionalParams.put("client", clientIP);
            }
        }
        return additionalParams;
    }

    PIResponse tryTriggerFirstStep(String username, PrivacyIDEA privacyIDEA, Configuration config, String currentPassword,
                                   Map<String, String> additionalParams, Map<String, String> headers)
    {
        // Try to trigger challenges if configured. Using a service account has precedence over sending the (static) password
        PIResponse triggerResponse = null;
        if (username != null)
        {
            if (config.triggerChallenge())
            {
                triggerResponse = privacyIDEA.triggerChallenges(username, additionalParams, headers);
            }
            else if (config.sendPassword())
            {
                if (currentPassword != null)
                {
                    triggerResponse = privacyIDEA.validateCheck(username, currentPassword, null, additionalParams, headers);
                }
                else
                {
                    logger.error("Cannot send password because it is null!");
                }
            }
            else if (config.sendStaticPass())
            {
                triggerResponse = privacyIDEA.validateCheck(username, config.staticPass(), null, additionalParams, headers);
            }
        }
        else
        {
            logger.error("Username is null, cannot trigger challenges.");
        }
        return triggerResponse;
    }

}