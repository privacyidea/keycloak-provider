/**
 * Copyright 2021 NetKnights GmbH - micha.preusser@netknights.it
 * nils.behlen@netknights.it
 * - Modified
 * <p>
 * Based on original code:
 * <p>
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.privacyidea.IPILogger;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;
import org.privacyidea.RolloutInfo;
import org.privacyidea.TokenInfo;
import org.privacyidea.U2F;

import static org.privacyidea.PIConstants.PASSWORD;
import static org.privacyidea.PIConstants.TOKEN_TYPE_PUSH;
import static org.privacyidea.PIConstants.TOKEN_TYPE_U2F;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;
import static org.privacyidea.authenticator.Const.AUTH_NOTE_ACCEPT_LANGUAGE;
import static org.privacyidea.authenticator.Const.AUTH_NOTE_AUTH_COUNTER;
import static org.privacyidea.authenticator.Const.AUTH_NOTE_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.DEFAULT_OTP_MESSAGE_DE;
import static org.privacyidea.authenticator.Const.DEFAULT_OTP_MESSAGE_EN;
import static org.privacyidea.authenticator.Const.DEFAULT_PUSH_MESSAGE_DE;
import static org.privacyidea.authenticator.Const.DEFAULT_PUSH_MESSAGE_EN;
import static org.privacyidea.authenticator.Const.FORM_ERROR;
import static org.privacyidea.authenticator.Const.FORM_FILE_NAME;
import static org.privacyidea.authenticator.Const.FORM_MODE;
import static org.privacyidea.authenticator.Const.FORM_MODE_CHANGED;
import static org.privacyidea.authenticator.Const.FORM_OTP;
import static org.privacyidea.authenticator.Const.FORM_OTP_AVAILABLE;
import static org.privacyidea.authenticator.Const.FORM_OTP_MESSAGE;
import static org.privacyidea.authenticator.Const.FORM_POLL_INTERVAL;
import static org.privacyidea.authenticator.Const.FORM_PUSH_AVAILABLE;
import static org.privacyidea.authenticator.Const.FORM_PUSH_MESSAGE;
import static org.privacyidea.authenticator.Const.FORM_TOKEN_ENROLLMENT_QR;
import static org.privacyidea.authenticator.Const.FORM_U2F_SIGN_REQUEST;
import static org.privacyidea.authenticator.Const.FORM_U2F_SIGN_RESPONSE;
import static org.privacyidea.authenticator.Const.FORM_UI_LANGUAGE;
import static org.privacyidea.authenticator.Const.FORM_WEBAUTHN_ORIGIN;
import static org.privacyidea.authenticator.Const.FORM_WEBAUTHN_SIGN_REQUEST;
import static org.privacyidea.authenticator.Const.FORM_WEBAUTHN_SIGN_RESPONSE;
import static org.privacyidea.authenticator.Const.HEADER_ACCEPT_LANGUAGE;
import static org.privacyidea.authenticator.Const.PLUGIN_USER_AGENT;
import static org.privacyidea.authenticator.Const.TRUE;

public class PrivacyIDEAAuthenticator implements org.keycloak.authentication.Authenticator, IPILogger
{
    private final Logger logger = Logger.getLogger(PrivacyIDEAAuthenticator.class);

    private final ConcurrentHashMap<String, Pair> piInstanceMap = new ConcurrentHashMap<>();
    private boolean logEnabled = false;

    /**
     * Create new instances of PrivacyIDEA and the Configuration. Also adds them to the instance map.
     *
     * @param configMap configuration of the current request
     * @param realm     realm of the current request
     * @return Pair of PrivacyIDEA and Configuration
     */
    private Pair createInstance(Map<String, String> configMap, String realm)
    {
        Configuration config = new Configuration(configMap);
        PrivacyIDEA privacyIDEA = PrivacyIDEA.newBuilder(config.serverURL(), PLUGIN_USER_AGENT)
                                             .sslVerify(config.sslVerify()).logger(this)
                                             .pollingIntervals(config.pollingInterval()).realm(config.realm())
                                             .serviceAccount(config.serviceAccountName(), config.serviceAccountPass())
                                             .serviceRealm(config.serviceAccountRealm()).build();
        Pair pair = new Pair(privacyIDEA, config);
        piInstanceMap.put(realm, pair);
        return pair;
    }

    /**
     * This function will be called when the authentication flow triggers the privacyIDEA execution.
     * i.e. after the username + password have been submitted.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void authenticate(AuthenticationFlowContext context)
    {
        // Get the configuration and privacyIDEA instance for the current realm
        // If none is found create new ones
        String kcRealm = context.getRealm().getName();
        Pair currentPair;
        if (piInstanceMap.containsKey(kcRealm))
        {
            currentPair = piInstanceMap.get(kcRealm);

            int incomingHash = context.getAuthenticatorConfig().getConfig().hashCode();
            if (incomingHash != currentPair.configuration().configHash())
            {
                currentPair = createInstance(context.getAuthenticatorConfig().getConfig(), kcRealm);
                log("Replacing privacyIDEA instance for realm " + kcRealm);
            }
        }
        else
        {
            currentPair = createInstance(context.getAuthenticatorConfig().getConfig(), kcRealm);
            log("Added new PI instance for realm " + kcRealm);
        }

        PrivacyIDEA privacyIDEA = currentPair.privacyIDEA();
        Configuration config = currentPair.configuration();
        logEnabled = config.doLog();
        // Get the things that were submitted in the first username+password form
        UserModel user = context.getUser();
        String currentUser = user.getUsername();

        // Check if the current user is member of an included or excluded group
        if (!config.includedGroups().isEmpty())
        {
            if (user.getGroupsStream().map(GroupModel::getName).noneMatch(config.includedGroups()::contains))
            {
                context.success();
                return;
            }
        }
        else if (!config.excludedGroups().isEmpty())
        {
            if (user.getGroupsStream().map(GroupModel::getName).anyMatch(config.excludedGroups()::contains))
            {
                context.success();
                return;
            }
        }

        String currentPassword = null;
        if (context.getHttpRequest().getDecodedFormParameters().get(PASSWORD) != null)
        {
            currentPassword = context.getHttpRequest().getDecodedFormParameters().get(PASSWORD).get(0);
        }

        // Get the language from the request headers to pass it to the ui and the privacyIDEA requests
        String acceptLanguage = context.getSession().getContext().getRequestHeaders().getRequestHeaders()
                                       .get(HEADER_ACCEPT_LANGUAGE).get(0);
        String uiLanguage = "en";
        Map<String, String> attachHeaders = new LinkedHashMap<>();
        if (acceptLanguage != null)
        {
            attachHeaders.put(HEADER_ACCEPT_LANGUAGE, acceptLanguage);
            if (acceptLanguage.toLowerCase().startsWith("de"))
            {
                uiLanguage = "de";
            }
        }

        // Attach headers set in config to the PI request
        if (!config.attachHeaders().isEmpty())
        {
            config.attachHeaders().forEach(header ->
                                      {
                                          String[] parts = header.split("=");
                                          String part1 = parts[0];
                                          String part2 = parts[1];

                                          attachHeaders.put(part1, part2);
                                      });
        }

        // Prepare for possibly triggering challenges
        PIResponse triggerResponse = null;
        String transactionID = null;
        String pushMessage = uiLanguage.equals("en") ? DEFAULT_PUSH_MESSAGE_EN : DEFAULT_PUSH_MESSAGE_DE;
        String otpMessage = uiLanguage.equals("en") ? DEFAULT_OTP_MESSAGE_EN : DEFAULT_OTP_MESSAGE_DE;

        // Variables to configure the UI
        boolean pushAvailable = false;
        boolean otpAvailable = true; // Always assume an OTP token
        String startingMode = "otp";
        String webAuthnSignRequest = "";
        String u2fSignRequest = "";

        // Trigger challenges if configured. Service account has precedence over send password
        if (config.triggerChallenge())
        {
            triggerResponse = privacyIDEA.triggerChallenges(currentUser, attachHeaders);
        }
        else if (config.sendPassword())
        {
            if (currentPassword != null)
            {
                triggerResponse = privacyIDEA.validateCheck(currentUser, currentPassword, null, attachHeaders);
            }
            else
            {
                log("Cannot send password because it is null!");
            }
        }

        // Evaluate for possibly triggered token
        if (triggerResponse != null)
        {
            if (triggerResponse.error != null)
            {
                context.form().setError(triggerResponse.error.message);
                context.form().setAttribute(FORM_ERROR, true);
            }

            transactionID = triggerResponse.transactionID;

            if (!triggerResponse.multiChallenge().isEmpty())
            {
                pushAvailable = triggerResponse.pushAvailable();
                if (pushAvailable)
                {
                    pushMessage = triggerResponse.pushMessage();
                }

                otpMessage = triggerResponse.otpMessage();

                // Check for WebAuthn and U2F
                if (triggerResponse.triggeredTokenTypes().contains(TOKEN_TYPE_WEBAUTHN))
                {
                    if (!triggerResponse.mergedSignRequest().isEmpty())
                    {
                        webAuthnSignRequest = triggerResponse.mergedSignRequest();
                    }
                }

                if (triggerResponse.triggeredTokenTypes().contains(TOKEN_TYPE_U2F))
                {
                    List<U2F> signRequests = triggerResponse.u2fSignRequests();
                    if (!signRequests.isEmpty())
                    {
                        u2fSignRequest = signRequests.get(0).signRequest();
                    }
                }
            }

            // Check if any triggered token matches the preferred token type
            if (triggerResponse.triggeredTokenTypes().contains(config.prefTokenType()))
            {
                startingMode = config.prefTokenType();
            }
        }

        // Enroll token if enabled and user does not have one. If something was triggered before, don't even try.
        String tokenEnrollmentQR = "";
        if (config.enrollToken() && (transactionID == null || transactionID.isEmpty()))
        {
            List<TokenInfo> tokenInfos = privacyIDEA.getTokenInfo(currentUser);

            if (tokenInfos == null || tokenInfos.isEmpty())
            {
                RolloutInfo rolloutInfo = privacyIDEA.tokenRollout(currentUser, config.enrollingTokenType());

                if (rolloutInfo != null)
                {
                    if (rolloutInfo.error == null)
                    {
                        tokenEnrollmentQR = rolloutInfo.googleurl.img;
                    }
                    else
                    {
                        context.form().setError(rolloutInfo.error.message);
                        context.form().setAttribute(FORM_ERROR, true);
                    }
                }
                else
                {
                    context.form().setError("Configuration error, please check the log file.");
                }
            }
        }

        // Prepare the form and auth notes to pass infos to the UI and the next step
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_AUTH_COUNTER, "0");
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_ACCEPT_LANGUAGE, acceptLanguage);

        if (transactionID != null && !transactionID.isEmpty())
        {
            context.getAuthenticationSession().setAuthNote(AUTH_NOTE_TRANSACTION_ID, transactionID);
        }

        Response responseForm = context.form().setAttribute(FORM_POLL_INTERVAL, config.pollingInterval().get(0))
                                       .setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                                       .setAttribute(FORM_MODE, startingMode)
                                       .setAttribute(FORM_PUSH_AVAILABLE, pushAvailable)
                                       .setAttribute(FORM_OTP_AVAILABLE, otpAvailable)
                                       .setAttribute(FORM_PUSH_MESSAGE, pushMessage)
                                       .setAttribute(FORM_OTP_MESSAGE, otpMessage)
                                       .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, webAuthnSignRequest)
                                       .setAttribute(FORM_U2F_SIGN_REQUEST, u2fSignRequest)
                                       .setAttribute(FORM_UI_LANGUAGE, uiLanguage).createForm(FORM_FILE_NAME);
        context.challenge(responseForm);
    }

    /**
     * This function will be called when the privacyIDEA form is submitted.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void action(AuthenticationFlowContext context)
    {
        String kcRealm = context.getRealm().getName();

        PrivacyIDEA privacyIDEA;
        Configuration config;
        if (piInstanceMap.containsKey(kcRealm))
        {
            Pair pair = piInstanceMap.get(kcRealm);
            privacyIDEA = pair.privacyIDEA();
            config = pair.configuration();
        }
        else
        {
            throw new AuthenticationFlowException("No privacyIDEA configuration found for kc-realm " + kcRealm,
                                                  AuthenticationFlowError.IDENTITY_PROVIDER_NOT_FOUND);
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel"))
        {
            context.cancelLogin();
            return;
        }
        LoginFormsProvider form = context.form();
        //logger.info("formData:");
        //formData.forEach((k, v) -> logger.info("key=" + k + ", value=" + v));

        // Get data from the privacyIDEA form
        String tokenEnrollmentQR = formData.getFirst(FORM_TOKEN_ENROLLMENT_QR);
        String currentMode = formData.getFirst(FORM_MODE);
        boolean pushToken = TRUE.equals(formData.getFirst(FORM_PUSH_AVAILABLE));
        boolean otpToken = TRUE.equals(formData.getFirst(FORM_OTP_AVAILABLE));
        String pushMessage = formData.getFirst(FORM_PUSH_MESSAGE);
        String otpMessage = formData.getFirst(FORM_OTP_MESSAGE);
        String tokenTypeChanged = formData.getFirst(FORM_MODE_CHANGED);
        String uiLanguage = formData.getFirst(FORM_UI_LANGUAGE);
        String transactionID = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_TRANSACTION_ID);
        String currentUserName = context.getUser().getUsername();

        // Reuse the accept-language for any requests made in this step
        String acceptLanguage = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_ACCEPT_LANGUAGE);
        Map<String, String> languageHeader = Collections.singletonMap(HEADER_ACCEPT_LANGUAGE, acceptLanguage);

        String webAuthnSignRequest = formData.getFirst(FORM_WEBAUTHN_SIGN_REQUEST);
        String webAuthnSignResponse = formData.getFirst(FORM_WEBAUTHN_SIGN_RESPONSE);
        // The origin is set by the form every time, no need to put it in the form again
        String origin = formData.getFirst(FORM_WEBAUTHN_ORIGIN);

        String u2fSignRequest = formData.getFirst(FORM_U2F_SIGN_REQUEST);
        String u2fSignResponse = formData.getFirst(FORM_U2F_SIGN_RESPONSE);

        // Prepare the failure message, the message from privacyIDEA will be appended if possible
        String authenticationFailureMessage = "Authentication failed.";

        // Set the "old" values again
        form.setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR).setAttribute(FORM_MODE, currentMode)
            .setAttribute(FORM_PUSH_AVAILABLE, pushToken).setAttribute(FORM_OTP_AVAILABLE, otpToken)
            .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, webAuthnSignRequest)
            .setAttribute(FORM_U2F_SIGN_REQUEST, u2fSignRequest).setAttribute(FORM_UI_LANGUAGE, uiLanguage);

        boolean didTrigger = false; // To not show the error message if something was triggered
        PIResponse response = null;

        // Send a request to privacyIDEA depending on the mode
        if (TOKEN_TYPE_PUSH.equals(currentMode))
        {
            // In push mode, poll for the transaction id to see if the challenge has been answered
            if (privacyIDEA.pollTransaction(transactionID))
            {
                // If the challenge has been answered, finalize with a call to validate check
                response = privacyIDEA.validateCheck(currentUserName, "", transactionID, languageHeader);
            }
        }
        else if (webAuthnSignResponse != null && !webAuthnSignResponse.isEmpty())
        {
            if (origin == null || origin.isEmpty())
            {
                logger.error("Origin is missing for WebAuthn authentication!");
            }
            else
            {
                response = privacyIDEA.validateCheckWebAuthn(currentUserName, transactionID, webAuthnSignResponse,
                                                             origin, languageHeader);
            }
        }
        else if (u2fSignResponse != null && !u2fSignResponse.isEmpty())
        {
            response = privacyIDEA.validateCheckU2F(currentUserName, transactionID, u2fSignResponse, languageHeader);
        }
        else if (!TRUE.equals(tokenTypeChanged))
        {
            String otp = formData.getFirst(FORM_OTP);
            // If the transaction id is not present, it will be not be added in validateCheck, so no need to check here
            response = privacyIDEA.validateCheck(currentUserName, otp, transactionID, languageHeader);
        }

        // Evaluate the response
        if (response != null)
        {
            // On success, finish the execution
            if (response.value)
            {
                context.success();
                return;
            }

            if (response.error != null)
            {
                form.setError(response.error.message);
                form.setAttribute(FORM_ERROR, true);
                context.failureChallenge(AuthenticationFlowError.INVALID_USER, form.createForm(FORM_FILE_NAME));
                return;
            }

            // If the authentication was not successful (yet), either the provided data was wrong
            // or another challenge was triggered
            if (!response.multiChallenge().isEmpty())
            {
                // A challenge was triggered, display its message and save the transaction id in the session
                otpMessage = response.message;
                context.getAuthenticationSession().setAuthNote(AUTH_NOTE_TRANSACTION_ID, response.transactionID);
                didTrigger = true;
            }
            else
            {
                // The authentication failed without triggering anything so the things that have been sent before were wrong
                authenticationFailureMessage += "\n" + response.message;
            }
        }

        // The authCounter is also used to determine the polling interval for push
        // If the authCounter is bigger than the size of the polling interval list, repeat the last value in the list
        int authCounter = Integer.parseInt(context.getAuthenticationSession().getAuthNote(AUTH_NOTE_AUTH_COUNTER)) + 1;
        authCounter = (authCounter >= config.pollingInterval().size() ? config.pollingInterval().size() - 1 :
                       authCounter);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_AUTH_COUNTER, Integer.toString(authCounter));

        // The message variables could be overwritten if a challenge was triggered. Therefore, add them here at the end
        form.setAttribute(FORM_POLL_INTERVAL, config.pollingInterval().get(authCounter))
            .setAttribute(FORM_PUSH_MESSAGE, (pushMessage == null ? DEFAULT_PUSH_MESSAGE_EN : pushMessage))
            .setAttribute(FORM_OTP_MESSAGE, (otpMessage == null ? DEFAULT_OTP_MESSAGE_EN : otpMessage));

        // Do not display the error if the token type was switched or if another challenge was triggered
        if (!(TRUE.equals(tokenTypeChanged)) && !didTrigger)
        {
            form.setError(TOKEN_TYPE_PUSH.equals(currentMode) ? "Authentication not verified yet." :
                          authenticationFailureMessage);
        }

        Response responseForm = form.createForm(FORM_FILE_NAME);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, responseForm);
    }

    @Override
    public boolean requiresUser()
    {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user)
    {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user)
    {
    }

    @Override
    public void close()
    {
    }

    // IPILogger implementation
    @Override
    public void log(String message)
    {
        if (logEnabled)
        {
            logger.info("PrivacyIDEA Client: " + message);
        }
    }

    @Override
    public void error(String message)
    {
        if (logEnabled)
        {
            logger.error("PrivacyIDEA Client: " + message);
        }
    }

    @Override
    public void log(Throwable t)
    {
        if (logEnabled)
        {
            logger.info("PrivacyIDEA Client: ", t);
        }
    }

    @Override
    public void error(Throwable t)
    {
        if (logEnabled)
        {
            logger.error("PrivacyIDEA Client: ", t);
        }
    }
}