package org.privacyidea.authenticator;

import java.util.ArrayList;
import java.util.List;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.privacyidea.Challenge;
import org.privacyidea.Constants;
import org.privacyidea.PILoggerBridge;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;
import org.privacyidea.RolloutInfo;
import org.privacyidea.TokenInfo;


/**
 * Copyright 2019 NetKnights GmbH - micha.preusser@netknights.it
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
public class PrivacyIDEAAuthenticator implements org.keycloak.authentication.Authenticator, PILoggerBridge {

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

        privacyIDEA = new PrivacyIDEA.Builder(config.getServerURL())
                .setSSLVerify(config.doSSLVerify())
                .setLogger(this)
                .setPollingIntervals(config.getPushtokenPollingInterval())
                .setRealm(config.getRealm())
                .setServiceAccount(config.getServiceAccountName(), config.getServiceAccountPass())
                .build();

        UserModel user = context.getUser();
        String currentUser = user.getUsername();
        String transactionID = null;

        // Check if privacyIDEA is enabled for the current user
        for (GroupModel groupModel : user.getGroups()) {
            for (String excludedGroup : config.getExcludedGroups()) {
                if (groupModel.getName().equals(excludedGroup)) {
                    context.success();
                    return;
                }
            }
        }

        // Trigger challenge for current user
        PIResponse triggerResponse = null;
        StringBuilder pushMessage = new StringBuilder(Const.DEFAULT_PUSH_MESSAGE);
        StringBuilder otpMessage = new StringBuilder(Const.DEFAULT_OTP_MESSAGE);
        // Always show an OTP field, if push is present is evaluated when triggering challenges
        boolean userHasPushToken = false;
        boolean userHasOTPToken = true;

        if (config.doTriggerChallenge()) {
            triggerResponse = privacyIDEA.triggerChallenges(currentUser);
            transactionID = triggerResponse.getTransactionID();

            if (triggerResponse.getMultiChallenge() != null) {
                pushMessage.setLength(0);
                pushMessage.append(triggerResponse
                        .getMultiChallenge()
                        .stream()
                        .filter(c -> c.getType().equals("push"))
                        .map(Challenge::getMessage)
                        .reduce("", (a, c) -> a + c + ", ").trim());

                if (pushMessage.length() > 0) {
                    pushMessage.deleteCharAt(pushMessage.length() - 1);
                }

                otpMessage.setLength(0);
                otpMessage.append(triggerResponse
                        .getMultiChallenge()
                        .stream()
                        .filter(c -> (c.getType().equals("hotp") || c.getType().equals("totp")))
                        .map(Challenge::getMessage)
                        .reduce("", (a, c) -> a + c + ", ").trim());

                if (otpMessage.length() > 0) {
                    otpMessage.deleteCharAt(otpMessage.length() - 1);
                }

                userHasPushToken = triggerResponse.getMultiChallenge().stream().anyMatch(c -> c.getType().equals("push"));
                // Any non-push token required an input field
                // userHasOTPToken = triggerResponse.getMultiChallenge().stream().anyMatch(c -> !c.getType().equals("push"));
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
        context.getAuthenticationSession().setAuthNote(Const.AUTH_NOTE_AUTH_COUNTER, "0");

        if (transactionID != null && !transactionID.isEmpty()) {
            context.getAuthenticationSession().setAuthNote(Const.AUTH_NOTE_TRANSACTION_ID, transactionID);
        }

        // Create login form
        String tokenType = userHasPushToken ? "push" : "otp";

        Response challenge = context.form()
                .setAttribute(Const.FORM_PUSHTOKEN_INTERVAL, config.getPushtokenPollingInterval().get(0))
                .setAttribute(Const.FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                .setAttribute(Const.FORM_TOKENTYPE, tokenType)
                .setAttribute(Const.FORM_PUSHTOKEN, userHasPushToken)
                .setAttribute(Const.FORM_OTPTOKEN, userHasOTPToken)
                .setAttribute(Const.FORM_PUSH_MESSAGE, pushMessage)
                .setAttribute(Const.FORM_OTP_MESSAGE, otpMessage)
                .createForm(Const.FORM_FILE_NAME);
        context.challenge(challenge);
    }

    /**
     * This function will be called if the user submitted the our form
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
        /*log.info("formData:");
        formData.forEach((k, v) -> log.info("key=" + k + ", value=" + v)); */

        // Get data from form
        String tokenEnrollmentQR = formData.getFirst(Const.FORM_TOKEN_ENROLLMENT_QR);
        String tokenType = formData.getFirst(Const.FORM_TOKENTYPE);
        boolean pushToken = formData.getFirst(Const.FORM_PUSHTOKEN).equals(Const.TRUE);
        boolean otpToken = formData.getFirst(Const.FORM_OTPTOKEN).equals(Const.TRUE);
        String pushMessage = formData.getFirst(Const.FORM_PUSH_MESSAGE);
        String otpMessage = formData.getFirst(Const.FORM_OTP_MESSAGE);
        String tokenTypeChanged = formData.getFirst(Const.FORM_TOKENTYPE_CHANGED);

        if (!validateResponse(context)) {
            int authCounter = Integer.parseInt(context.getAuthenticationSession().getAuthNote(Const.AUTH_NOTE_AUTH_COUNTER)) + 1;
            authCounter = (authCounter >= config.getPushtokenPollingInterval().size() ? config.getPushtokenPollingInterval().size() - 1 : authCounter);
            context.getAuthenticationSession().setAuthNote(Const.AUTH_NOTE_AUTH_COUNTER, Integer.toString(authCounter));

            LoginFormsProvider form = context.form()
                    .setAttribute(Const.FORM_PUSHTOKEN_INTERVAL, config.getPushtokenPollingInterval().get(authCounter))
                    .setAttribute(Const.FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                    .setAttribute(Const.FORM_TOKENTYPE, tokenType)
                    .setAttribute(Const.FORM_PUSHTOKEN, pushToken)
                    .setAttribute(Const.FORM_OTPTOKEN, otpToken)
                    .setAttribute(Const.FORM_PUSH_MESSAGE, pushMessage == null ? Const.DEFAULT_PUSH_MESSAGE : pushMessage)
                    .setAttribute(Const.FORM_OTP_MESSAGE, otpMessage == null ? Const.DEFAULT_OTP_MESSAGE : otpMessage);

            // Dont display the error if the token type was switched
            if (!tokenTypeChanged.equals(Const.TRUE)) {
                form.setError(tokenType.equals(Const.TOKEN_TYPE_PUSH) ? "Authentication not verified yet." : "Authentication failed.");
            }

            Response challenge = form.createForm(Const.FORM_FILE_NAME);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }
        context.success();
    }

    /**
     * Check if authentication is successful
     *
     * @param context AuthenticationFlowContext
     * @return true if authentication was successful, else false
     */
    private boolean validateResponse(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.getFirst(Const.FORM_TOKENTYPE_CHANGED).equals(Const.TRUE)) {
            return false;
        }

        // Get data from form
        String tokenEnrollmentQR = formData.getFirst(Const.FORM_TOKEN_ENROLLMENT_QR);
        String tokenType = formData.getFirst(Const.FORM_TOKENTYPE);
        String transactionID = context.getAuthenticationSession().getAuthNote(Const.AUTH_NOTE_TRANSACTION_ID);
        String currentUserName = context.getUser().getUsername();

        if (tokenType.equals(Const.TOKEN_TYPE_PUSH)) {

            if (privacyIDEA.pollTransaction(transactionID)) {
                PIResponse response = privacyIDEA.validateCheck(currentUserName, "", transactionID);
                return response.getValue();
            }
            return false;
        }

        String otp = formData.getFirst(Const.FORM_PI_OTP);
        PIResponse response = privacyIDEA.validateCheck(currentUserName, otp);

        return response != null && response.getValue();
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
