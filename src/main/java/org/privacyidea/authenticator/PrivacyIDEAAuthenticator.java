/*
 * Copyright 2021 NetKnights GmbH - micha.preusser@netknights.it
 * nils.behlen@netknights.it
 * - Modified
 *
 * Based on original code:
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea.authenticator;

import java.util.Collections;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.privacyidea.*;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Optional;

import static org.privacyidea.PIConstants.PASSWORD;
import static org.privacyidea.PIConstants.TOKEN_TYPE_PUSH;
import static org.privacyidea.PIConstants.TOKEN_TYPE_WEBAUTHN;
import static org.privacyidea.authenticator.Const.*;

public class PrivacyIDEAAuthenticator implements org.keycloak.authentication.Authenticator, IPILogger {

    private final Logger logger = Logger.getLogger(PrivacyIDEAAuthenticator.class);

    private Configuration config;
    private PrivacyIDEA privacyIDEA;

    /**
     * This function will be called when the authentication flow triggers the privacyIDEA execution.
     * i.e. after the username + password have been submitted.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        config = new Configuration(context.getAuthenticatorConfig().getConfig());

        privacyIDEA = new PrivacyIDEA.Builder(config.getServerURL(), PLUGIN_USER_AGENT)
                .setSSLVerify(config.doSSLVerify())
                .setLogger(this)
                .setPollingIntervals(config.getPollingInterval())
                .setRealm(config.getRealm())
                .setServiceAccount(config.getServiceAccountName(), config.getServiceAccountPass())
                .setServiceAccountRealm(config.getServiceAccountRealm())
                .build();

        // Get the things that were submitted in the first username+password form
        UserModel user = context.getUser();
        String currentUser = user.getUsername();
        String currentPassword = null;

        //log("[authenticate] http form params: " + context.getHttpRequest().getDecodedFormParameters().toString());
        if (context.getHttpRequest().getDecodedFormParameters().get(PASSWORD) != null) {
            currentPassword = context.getHttpRequest().getDecodedFormParameters().get(PASSWORD).get(0);
        }

        // Check if the current user is member of an excluded group
        for (GroupModel groupModel : user.getGroups()) {
            for (String excludedGroup : config.getExcludedGroups()) {
                if (excludedGroup.equals(groupModel.getName())) {
                    context.success();
                    return;
                }
            }
        }

        // Get the language from the request headers to pass it to the ui and the privacyIDEA requests
        String acceptLanguage = context.getSession().getContext().getRequestHeaders().getRequestHeaders().get(HEADER_ACCEPT_LANGUAGE).get(0);
        String uiLanguage = "en";
        Map<String, String> languageHeader = Collections.emptyMap();
        if (acceptLanguage != null) {
            languageHeader = Collections.singletonMap(HEADER_ACCEPT_LANGUAGE, acceptLanguage);
            if (acceptLanguage.toLowerCase().startsWith("de")) {
                uiLanguage = "de";
            }
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

        // Trigger challenges if configured. Service account has precedence over send password
        if (config.doTriggerChallenge()) {
            triggerResponse = privacyIDEA.triggerChallenges(currentUser, languageHeader);
        } else if (config.doSendPassword()) {
            if (currentPassword != null) {
                triggerResponse = privacyIDEA.validateCheck(currentUser, currentPassword, languageHeader);
            } else {
                log("Cannot send password because it is null!");
            }
        }

        // Evaluate for possibly triggered token
        if (triggerResponse != null) {
            transactionID = triggerResponse.getTransactionID();

            if (!triggerResponse.getMultiChallenge().isEmpty()) {

                pushAvailable = triggerResponse.isPushAvailable();
                if (pushAvailable) {
                    pushMessage = triggerResponse.getPushMessage();
                }

                otpMessage = triggerResponse.getOTPMessage();

                // Check for WebAuthnSignRequest
                // TODO currently only gets the first sign request
                if (triggerResponse.getTriggeredTokenTypes().contains(TOKEN_TYPE_WEBAUTHN)) {
                    List<WebAuthn> signRequests = triggerResponse.getWebAuthnSignRequests();
                    if (!signRequests.isEmpty()) {
                        webAuthnSignRequest = signRequests.get(0).getSignRequest();
                    }
                }
            }

            // Check if any triggered token matches the preferred token type
            if (triggerResponse.getTriggeredTokenTypes().contains(config.getPrefTokenType())) {
                startingMode = config.getPrefTokenType();
            }
        }

        // Enroll token if enabled and user does not have one
        String tokenEnrollmentQR = "";
        if (config.doEnrollToken()) {
            List<TokenInfo> tokenInfos = privacyIDEA.getTokenInfo(currentUser);

            if (tokenInfos == null || tokenInfos.isEmpty()) {
                RolloutInfo rolloutInfo = privacyIDEA.tokenRollout(currentUser, config.getEnrollingTokenType());
                tokenEnrollmentQR = rolloutInfo.googleurl.img;
            }
        }

        // Prepare the form and auth notes to pass infos to the UI or the next step
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_AUTH_COUNTER, "0");
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_ACCEPT_LANGUAGE, acceptLanguage);

        if (transactionID != null && !transactionID.isEmpty()) {
            context.getAuthenticationSession().setAuthNote(AUTH_NOTE_TRANSACTION_ID, transactionID);
        }

        Response responseForm = context.form()
                .setAttribute(FORM_POLL_INTERVAL, config.getPollingInterval().get(0))
                .setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                .setAttribute(FORM_MODE, startingMode)
                .setAttribute(FORM_PUSH_AVAILABLE, pushAvailable)
                .setAttribute(FORM_OTP_AVAILABLE, otpAvailable)
                .setAttribute(FORM_PUSH_MESSAGE, pushMessage.toString())
                .setAttribute(FORM_OTP_MESSAGE, otpMessage.toString())
                .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, webAuthnSignRequest)
                .setAttribute(FORM_UI_LANGUAGE, uiLanguage)
                .createForm(FORM_FILE_NAME);
        context.challenge(responseForm);
    }

    /**
     * This function will be called when our form is submitted.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        LoginFormsProvider form = context.form();

        //logger.info("formData:");
        //formData.forEach((k, v) -> logger.info("key=" + k + ", value=" + v));

        // Get data from form
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

        // Reuse the accept language for any requests made in this step
        String acceptLanguage = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_ACCEPT_LANGUAGE);
        Map<String, String> languageHeader = Collections.singletonMap(HEADER_ACCEPT_LANGUAGE, acceptLanguage);

        String webAuthnSignRequest = formData.getFirst(FORM_WEBAUTHN_SIGN_REQUEST);
        String webAuthnSignResponse = formData.getFirst(FORM_WEBAUTHN_SIGN_RESPONSE);
        // The origin is set by the form every time, no need to put it in the form again
        String origin = formData.getFirst(FORM_WEBAUTHN_ORIGIN);

        // Prepare the failure message, the message from privacyIDEA will be appended if possible
        String authenticationFailureMessage = "Authentication failed.";

        // Set the "old" values again
        form.setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                .setAttribute(FORM_MODE, currentMode)
                .setAttribute(FORM_PUSH_AVAILABLE, pushToken)
                .setAttribute(FORM_OTP_AVAILABLE, otpToken)
                .setAttribute(FORM_WEBAUTHN_SIGN_REQUEST, webAuthnSignRequest)
                .setAttribute(FORM_UI_LANGUAGE, uiLanguage);

        boolean didTrigger = false; // To not show the error message if something was triggered
        PIResponse response = null;

        // Determine to which endpoint we send the data from the form based on the mode the form was in
        // Or if a WebAuthnSignResponse is present
        if (TOKEN_TYPE_PUSH.equals(currentMode)) {
            // In push mode, we poll for the transaction id to see if the challenge has been answered
            if (privacyIDEA.pollTransaction(transactionID)) {
                // If the challenge has been answered, finalize with a call to validate check
                response = privacyIDEA.validateCheck(currentUserName, "", transactionID, languageHeader);
            }
        } else if (webAuthnSignResponse != null && !webAuthnSignResponse.isEmpty()) {
            if (origin == null || origin.isEmpty()) {
                logger.error("Origin is missing for WebAuthn authentication!");
            } else {
                response = privacyIDEA.validateCheckWebAuthn(currentUserName, transactionID, webAuthnSignResponse, origin, languageHeader);
            }
        } else {

            if (!(TRUE.equals(tokenTypeChanged))) {
                String otp = formData.getFirst(FORM_OTP);
                // If the transaction id is not present, it will be not be added in validateCheck, so no need to check here
                response = privacyIDEA.validateCheck(currentUserName, otp, transactionID, languageHeader);
            }
        }

        // Evaluate the response
        if (response != null) {
            // On success we finish our execution
            if (response.getValue()) {
                context.success();
                return;
            }

            // If the authentication was not successful (yet), either the provided data was wrong
            // or another challenge was triggered
            if (!response.getMultiChallenge().isEmpty()) {
                // A challenge was triggered, display its message and save the transaction id in the session
                otpMessage = response.getMessage();
                context.getAuthenticationSession().setAuthNote(AUTH_NOTE_TRANSACTION_ID, response.getTransactionID());
                didTrigger = true;
            } else {
                // The authentication failed without triggering anything so the things that have been sent before were wrong
                authenticationFailureMessage += "\n" + response.getMessage();
            }
        }

        // The authCounter is also used to determine the polling interval for push
        // If the authCounter is bigger than the size of the polling interval list, repeat the lists last value
        int authCounter = Integer.parseInt(context.getAuthenticationSession().getAuthNote(AUTH_NOTE_AUTH_COUNTER)) + 1;
        authCounter = (authCounter >= config.getPollingInterval().size() ? config.getPollingInterval().size() - 1 : authCounter);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_AUTH_COUNTER, Integer.toString(authCounter));

        // The message variables could be overwritten if a challenge was triggered. Therefore, add them here at the end
        form.setAttribute(FORM_POLL_INTERVAL, config.getPollingInterval().get(authCounter))
                .setAttribute(FORM_PUSH_MESSAGE, (pushMessage == null ? DEFAULT_PUSH_MESSAGE_EN : pushMessage))
                .setAttribute(FORM_OTP_MESSAGE, (otpMessage == null ? DEFAULT_OTP_MESSAGE_EN : otpMessage));

        // Do not display the error if the token type was switched or if another challenge was triggered
        if (!(TRUE.equals(tokenTypeChanged)) && !didTrigger) {
            form.setError(TOKEN_TYPE_PUSH.equals(currentMode) ? "Authentication not verified yet." : authenticationFailureMessage);
        }

        Response responseForm = form.createForm(FORM_FILE_NAME);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, responseForm);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
        // Just to make sure
        privacyIDEA.stopPolling();
    }

    // IPILogger implementation
    @Override
    public void log(String message) {
        if (config.doLog()) {
            logger.info(message);
        }
    }

    @Override
    public void error(String message) {
        if (config.doLog()) {
            logger.error(message);
        }
    }

    @Override
    public void log(Throwable t) {
        if (config.doLog()) {
            logger.info(t);
        }
    }

    @Override
    public void error(Throwable t) {
        if (config.doLog()) {
            logger.error(t);
        }
    }
}
