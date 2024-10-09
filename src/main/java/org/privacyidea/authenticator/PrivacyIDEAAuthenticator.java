/*
 * Copyright 2023 NetKnights GmbH - micha.preusser@netknights.it
 * nils.behlen@netknights.it
 * lukas.matusiewicz@netknights.it
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

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.common.Version;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.privacyidea.Challenge;
import org.privacyidea.IPILogger;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;
import org.privacyidea.RolloutInfo;
import org.privacyidea.TokenInfo;

import static org.privacyidea.PIConstants.PASSWORD;
import static org.privacyidea.PIConstants.TOKEN_TYPE_PUSH;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;
import static org.privacyidea.authenticator.Const.AUTH_NOTE_AUTH_COUNTER;
import static org.privacyidea.authenticator.Const.AUTH_NOTE_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.DEFAULT_OTP_MESSAGE_DE;
import static org.privacyidea.authenticator.Const.DEFAULT_OTP_MESSAGE_EN;
import static org.privacyidea.authenticator.Const.DEFAULT_PUSH_MESSAGE_DE;
import static org.privacyidea.authenticator.Const.DEFAULT_PUSH_MESSAGE_EN;
import static org.privacyidea.authenticator.Const.FORM_ERROR;
import static org.privacyidea.authenticator.Const.FORM_ERROR_MESSAGE;
import static org.privacyidea.authenticator.Const.FORM_FILE_NAME;
import static org.privacyidea.authenticator.Const.FORM_IMAGE_OTP;
import static org.privacyidea.authenticator.Const.FORM_IMAGE_PUSH;
import static org.privacyidea.authenticator.Const.FORM_IMAGE_WEBAUTHN;
import static org.privacyidea.authenticator.Const.FORM_MODE;
import static org.privacyidea.authenticator.Const.FORM_MODE_CHANGED;
import static org.privacyidea.authenticator.Const.FORM_OTP;
import static org.privacyidea.authenticator.Const.FORM_OTP_AVAILABLE;
import static org.privacyidea.authenticator.Const.FORM_AUTO_SUBMIT_OTP_LENGTH;
import static org.privacyidea.authenticator.Const.FORM_OTP_MESSAGE;
import static org.privacyidea.authenticator.Const.FORM_PI_POLL_IN_BROWSER_URL;
import static org.privacyidea.authenticator.Const.FORM_POLL_INTERVAL;
import static org.privacyidea.authenticator.Const.FORM_POLL_IN_BROWSER_FAILED;
import static org.privacyidea.authenticator.Const.FORM_PUSH_AVAILABLE;
import static org.privacyidea.authenticator.Const.FORM_PUSH_MESSAGE;
import static org.privacyidea.authenticator.Const.FORM_TOKEN_ENROLLMENT_QR;
import static org.privacyidea.authenticator.Const.FORM_TRANSACTION_ID;
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
     * Create new instances of PrivacyIDEA and the Configuration, if it does not exist yet.
     * Also adds them to the instance map.
     *
     * @param context for authentication flow
     */
    private Pair loadConfiguration(final AuthenticationFlowContext context)
    {
        // Get the configuration and privacyIDEA instance for the current realm
        // If none is found then create a new one
        final int incomingHash = context.getAuthenticatorConfig().getConfig().hashCode();
        final String kcRealm = context.getRealm().getName();
        final Pair currentPair = piInstanceMap.get(kcRealm);

        if (currentPair == null || incomingHash != currentPair.configuration().configHash())
        {
            final Map<String, String> configMap = context.getAuthenticatorConfig().getConfig();
            Configuration config = new Configuration(configMap);
            String kcVersion = Version.VERSION;
            String providerVersion = PrivacyIDEAAuthenticator.class.getPackage().getImplementationVersion();
            String fullUserAgent = PLUGIN_USER_AGENT + "/" + providerVersion + " Keycloak/" + kcVersion;
            PrivacyIDEA privacyIDEA = PrivacyIDEA.newBuilder(config.serverURL(), fullUserAgent)
                                                 .sslVerify(config.sslVerify())
                                                 .logger(this)
                                                 .realm(config.realm())
                                                 .serviceAccount(config.serviceAccountName(), config.serviceAccountPass())
                                                 .serviceRealm(config.serviceAccountRealm())
                                                 .build();

            // Close the old privacyIDEA instance to shut down the thread pool before replacing it in the map
            if (currentPair != null)
            {
                try
                {
                    currentPair.privacyIDEA().close();
                }
                catch (IOException e)
                {
                    error("Failed to close privacyIDEA instance!");
                }
            }
            Pair pair = new Pair(privacyIDEA, config);
            piInstanceMap.put(kcRealm, pair);
        }

        return piInstanceMap.get(kcRealm);
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
        final Pair currentPair = loadConfiguration(context);

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

        // In some cases, there will be no FormParameters so check if it is possible to even get the password
        if (config.sendPassword() && context.getHttpRequest() != null && context.getHttpRequest().getDecodedFormParameters() != null &&
            context.getHttpRequest().getDecodedFormParameters().get(PASSWORD) != null)
        {
            currentPassword = context.getHttpRequest().getDecodedFormParameters().get(PASSWORD).get(0);
        }

        Map<String, String> headers = getHeadersToForward(context, config);

        // Set UI language
        String uiLanguage = "en";
        if (headers.get(HEADER_ACCEPT_LANGUAGE) != null && headers.get(HEADER_ACCEPT_LANGUAGE).startsWith("de"))
        {
            uiLanguage = "de";
        }

        // Prepare for possibly triggering challenges
        PIResponse triggerResponse = null;
        String pushMessage = uiLanguage.equals("en") ? DEFAULT_PUSH_MESSAGE_EN : DEFAULT_PUSH_MESSAGE_DE;
        String otpMessage = uiLanguage.equals("en") ? DEFAULT_OTP_MESSAGE_EN : DEFAULT_OTP_MESSAGE_DE;
        if (!config.defaultOTPMessage().isEmpty())
        {
            otpMessage = config.defaultOTPMessage();
        }
        // Set the default values, always assume OTP is available
        String tokenEnrollmentQR = "";
        context.form()
               .setAttribute(FORM_MODE, "otp")
               .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, "")
               .setAttribute(FORM_PUSH_MESSAGE, pushMessage)
               .setAttribute(FORM_OTP_AVAILABLE, true)
               .setAttribute(FORM_OTP_MESSAGE, otpMessage)
               .setAttribute(FORM_PUSH_AVAILABLE, false)
               .setAttribute(FORM_IMAGE_PUSH, "")
               .setAttribute(FORM_IMAGE_OTP, "")
               .setAttribute(FORM_IMAGE_WEBAUTHN, "")
               .setAttribute(FORM_AUTO_SUBMIT_OTP_LENGTH, config.otpLength())
               .setAttribute(FORM_POLL_IN_BROWSER_FAILED, false)
               .setAttribute(FORM_POLL_INTERVAL, config.pollingInterval().get(0));

        // Trigger challenges if configured. Service account has precedence over send password
        if (config.triggerChallenge())
        {
            triggerResponse = privacyIDEA.triggerChallenges(currentUser, headers);
        }
        else if (config.sendPassword())
        {
            if (currentPassword != null)
            {
                triggerResponse = privacyIDEA.validateCheck(currentUser, currentPassword, null, headers);
            }
            else
            {
                log("Cannot send password because it is null!");
            }
        }
        else if (config.sendStaticPass())
        {
            triggerResponse = privacyIDEA.validateCheck(currentUser, config.staticPass(), null, headers);
        }

        // Evaluate for possibly triggered token
        if (triggerResponse != null)
        {
            if (triggerResponse.value)
            {
                context.success();
                return;
            }

            if (triggerResponse.error != null)
            {
                context.form().setError(triggerResponse.error.message);
                context.form().setAttribute(FORM_ERROR, true);
            }

            if (!triggerResponse.multichallenge.isEmpty())
            {
                extractChallengeDataToForm(triggerResponse, context, config);
            }

            // Enroll token if enabled and user does not have one. If something was triggered before, don't even try.
            if (config.enrollToken() && (triggerResponse.transactionID == null || triggerResponse.transactionID.isEmpty()))
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
        }
        // Prepare the form and auth notes to pass infos to the UI and the next step
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_AUTH_COUNTER, "0");

        Response responseForm = context.form()
                                       .setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                                       .setAttribute(FORM_UI_LANGUAGE, uiLanguage)
                                       .createForm(FORM_FILE_NAME);

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
        loadConfiguration(context);
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
        boolean pushAvailable = TRUE.equals(formData.getFirst(FORM_PUSH_AVAILABLE));
        boolean otpAvailable = TRUE.equals(formData.getFirst(FORM_OTP_AVAILABLE));
        boolean pollInBrowserFailed = TRUE.equals(formData.getFirst(FORM_POLL_IN_BROWSER_FAILED));
        String pushMessage = formData.getFirst(FORM_PUSH_MESSAGE);
        String otpMessage = formData.getFirst(FORM_OTP_MESSAGE);
        String imagePush = formData.getFirst(FORM_IMAGE_PUSH);
        String imageOTP = formData.getFirst(FORM_IMAGE_OTP);
        String imageWebauthn = formData.getFirst(FORM_IMAGE_WEBAUTHN);
        String otpLength = formData.getFirst(FORM_AUTO_SUBMIT_OTP_LENGTH);
        String tokenTypeChanged = formData.getFirst(FORM_MODE_CHANGED);
        String uiLanguage = formData.getFirst(FORM_UI_LANGUAGE);
        String transactionID = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_TRANSACTION_ID);
        String currentUserName = context.getUser().getUsername();
        String webAuthnSignRequest = formData.getFirst(FORM_WEBAUTHN_SIGN_REQUEST);
        String webAuthnSignResponse = formData.getFirst(FORM_WEBAUTHN_SIGN_RESPONSE);
        // The origin is set by the form every time, no need to put it in the form again
        String origin = formData.getFirst(FORM_WEBAUTHN_ORIGIN);

        // Prepare the failure message, the message from privacyIDEA will be appended if possible
        String authenticationFailureMessage = "Authentication failed.";

        // Set the "old" values again
        form.setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
            .setAttribute(FORM_MODE, currentMode)
            .setAttribute(FORM_PUSH_AVAILABLE, pushAvailable)
            .setAttribute(FORM_OTP_AVAILABLE, otpAvailable)
            .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, webAuthnSignRequest)
            .setAttribute(FORM_IMAGE_PUSH, imagePush)
            .setAttribute(FORM_IMAGE_OTP, imageOTP)
            .setAttribute(FORM_IMAGE_WEBAUTHN, imageWebauthn)
            .setAttribute(FORM_UI_LANGUAGE, uiLanguage)
            .setAttribute(FORM_AUTO_SUBMIT_OTP_LENGTH, otpLength)
            .setAttribute(FORM_POLL_IN_BROWSER_FAILED, pollInBrowserFailed)
            .setAttribute(FORM_PUSH_MESSAGE, (pushMessage == null ? DEFAULT_PUSH_MESSAGE_EN : pushMessage))
            .setAttribute(FORM_OTP_MESSAGE, (otpMessage == null ? DEFAULT_OTP_MESSAGE_EN : otpMessage));

        // Log the error encountered in the browser
        String error = formData.getFirst(FORM_ERROR_MESSAGE);
        if (error != null && !error.isEmpty())
        {
            logger.error(error);
        }

        Map<String, String> headers = getHeadersToForward(context, config);
        // Do not show the error message if something was triggered
        boolean didTrigger = false;
        PIResponse response = null;

        // Send a request to privacyIDEA depending on the mode
        if (TOKEN_TYPE_PUSH.equals(currentMode))
        {
            // In push mode, poll for the transaction id to see if the challenge has been answered
            if (privacyIDEA.pollTransaction(transactionID))
            {
                // If the challenge has been answered, finalize with a call to validate check
                response = privacyIDEA.validateCheck(currentUserName, "", transactionID, headers);
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
                response = privacyIDEA.validateCheckWebAuthn(currentUserName, transactionID, webAuthnSignResponse, origin, headers);
            }
        }
        else if (!TRUE.equals(tokenTypeChanged))
        {
            String otp = formData.getFirst(FORM_OTP);
            // If the transaction id is not present, it will be not be added in validateCheck, so no need to check here
            response = privacyIDEA.validateCheck(currentUserName, otp, transactionID, headers);
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
            if (!response.multichallenge.isEmpty())
            {
                extractChallengeDataToForm(response, context, config);
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
        authCounter = (authCounter >= config.pollingInterval().size() ? config.pollingInterval().size() - 1 : authCounter);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_AUTH_COUNTER, Integer.toString(authCounter));

        // The message variables could be overwritten if a challenge was triggered. Therefore, add them here at the end
        form.setAttribute(FORM_POLL_INTERVAL, config.pollingInterval().get(authCounter));

        // Do not display the error if the token type was switched or if another challenge was triggered
        if (!(TRUE.equals(tokenTypeChanged)) && !didTrigger)
        {
            form.setError(TOKEN_TYPE_PUSH.equals(currentMode) ? "Authentication not verified yet." : authenticationFailureMessage);
        }

        Response responseForm = form.createForm(FORM_FILE_NAME);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, responseForm);
    }

    private void extractChallengeDataToForm(PIResponse response, AuthenticationFlowContext context, Configuration config)
    {
        if (context == null || config == null)
        {
            error("extractChallengeDataToForm missing parameter!");
            return;
        }

        // Variables to configure the UI
        String webAuthnSignRequest = "";
        String mode = "otp";
        String newOtpMessage = response.otpMessage();
        if (response.transactionID != null && !response.transactionID.isEmpty())
        {
            context.getAuthenticationSession().setAuthNote(AUTH_NOTE_TRANSACTION_ID, response.transactionID);
        }

        // Check for the images
        List<Challenge> multiChallenge = response.multichallenge;
        for (Challenge c : multiChallenge)
        {
            if ("poll".equals(c.getClientMode()))
            {
                context.form().setAttribute(FORM_IMAGE_PUSH, c.getImage());
            }
            else if ("interactive".equals(c.getClientMode()))
            {
                context.form().setAttribute(FORM_IMAGE_OTP, c.getImage());
            }
            if ("webauthn".equals(c.getClientMode()))
            {
                context.form().setAttribute(FORM_IMAGE_WEBAUTHN, c.getImage());
            }
        }

        // Check for poll in browser
        if (config.pollInBrowser())
        {
            context.form().setAttribute(FORM_TRANSACTION_ID, response.transactionID);
            newOtpMessage = response.otpMessage() + "\n" + response.pushMessage();
            context.form()
                   .setAttribute(FORM_PI_POLL_IN_BROWSER_URL,
                                 config.pollInBrowserUrl().isEmpty() ? config.serverURL() : config.pollInBrowserUrl());
        }

        // Check for Push
        if (response.pushAvailable())
        {
            context.form().setAttribute(FORM_PUSH_AVAILABLE, true);
            context.form().setAttribute(FORM_PUSH_MESSAGE, response.pushMessage());
        }

        // Check for WebAuthn
        if (response.triggeredTokenTypes().contains(TOKEN_TYPE_WEBAUTHN))
        {
            webAuthnSignRequest = response.mergedSignRequest();
        }

        // Check if response from server contains preferred client mode
        if (response.preferredClientMode != null && !response.preferredClientMode.isEmpty())
        {
            mode = response.preferredClientMode;
        }
        else
        {
            // Alternatively check if any triggered token matches the local preferred token type
            if (response.triggeredTokenTypes().contains(config.prefTokenType()))
            {
                mode = config.prefTokenType();
            }
        }
        // Using poll in browser does not require push mode
        if (mode.equals("push") && config.pollInBrowser())
        {
            mode = "otp";
        }

        context.form()
               .setAttribute(FORM_MODE, mode)
               .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, webAuthnSignRequest)
               .setAttribute(FORM_OTP_MESSAGE, newOtpMessage);
    }

    /**
     * Extract the headers that should be forwarded to privacyIDEA from the original request to keycloak. The header names
     * can be defined in the configuration of this provider. The accept-language header is included by default.
     *
     * @param context AuthenticationFlowContext
     * @param config  Configuration
     * @return Map of headers
     */
    private Map<String, String> getHeadersToForward(AuthenticationFlowContext context, Configuration config)
    {
        Map<String, String> headersToForward = new LinkedHashMap<>();
        // Take all headers from config plus accept-language
        config.forwardedHeaders().add(HEADER_ACCEPT_LANGUAGE);

        for (String header : config.forwardedHeaders().stream().distinct().collect(Collectors.toList()))
        {
            List<String> headerValues = context.getSession().getContext().getRequestHeaders().getRequestHeaders().get(header);

            if (headerValues != null && !headerValues.isEmpty())
            {
                String temp = String.join(",", headerValues);
                headersToForward.put(header, temp);
            }
            else
            {
                log("No values for header " + header + " found.");
            }
        }
        return headersToForward;
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