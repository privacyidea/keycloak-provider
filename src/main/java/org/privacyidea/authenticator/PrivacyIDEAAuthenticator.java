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

        privacyIDEA.setLogExcludedEndpoints(new ArrayList<String>() {{
            add(Constants.ENDPOINT_VALIDATE_CHECK);
            add(Constants.ENDPOINT_POLL_TRANSACTION);
            add(Constants.ENDPOINT_AUTH);
        }});

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
        int tokenCounter = 0;
        //String tokenType = TOKEN_TYPE_OTP;
        // Check which kinds of tokens the user has to adapt the options of the form
        //boolean userHasPushToken = false;
        //boolean userHasOTPToken = false;
        // Collect the messages for the tokens to display
        //List<String> pushMessages = new ArrayList<>();
        //List<String> otpMessages = new ArrayList<>();
        PIResponse triggerResponse = null;

        String pushMessage = Const.DEFAULT_PUSH_MESSAGE;
        String otpMessage = Const.DEFAULT_OTP_MESSAGE;
        boolean userHasPushToken = false;
        boolean userHasOTPToken = true;

        if (config.doTriggerChallenge()) {
            triggerResponse = privacyIDEA.triggerChallenges(currentUser);
            transactionID = triggerResponse.getTransactionID();

            if (triggerResponse.getMultiChallenge() != null) {
                pushMessage = triggerResponse
                        .getMultiChallenge()
                        .stream()
                        .filter(c -> c.getType().equals("push"))
                        .map(Challenge::getMessage)
                        .reduce("", (a, c) -> a + c + ", ").trim();

                otpMessage = triggerResponse
                        .getMultiChallenge()
                        .stream()
                        .filter(c -> (c.getType().equals("hotp") || c.getType().equals("totp")))
                        .map(Challenge::getMessage)
                        .reduce("", (a, c) -> a + c + ", ").trim();

                userHasPushToken = triggerResponse.getMultiChallenge().stream().anyMatch(c -> c.getType().equals("push"));
                // Any non-push token required an input field
                // userHasOTPToken = triggerResponse.getMultiChallenge().stream().anyMatch(c -> !c.getType().equals("push"));
            }

           /* Map<String, String> params = new HashMap<>();
            params.put(PARAM_KEY_USER, currentUser);
            JsonObject body = endpoint.sendRequest(ENDPOINT_TRIGGERCHALLENGE, params, true, POST);
            if (body != null) {
                JsonObject detail = body.getJsonObject(JSON_KEY_DETAIL);
                if (detail != null) {
                    JsonObject result = body.getJsonObject(JSON_KEY_RESULT);
                    tokenCounter = result.getInt(JSON_KEY_VALUE);
                    if (tokenCounter > 0) {
                        transactionID = detail.getString(JSON_KEY_TRANSACTION_ID);
                        JsonArray multi_challenge = detail.getJsonArray(JSON_KEY_MULTI_CHALLENGE);
                        for (int i = 0; i < multi_challenge.size(); i++) {
                            JsonObject challenge = multi_challenge.getJsonObject(i);
                            String msg = challenge.getString(JSON_KEY_MESSAGE);
                            if (challenge.getString(JSON_KEY_TYPE).equals(TOKEN_TYPE_PUSH)) {
                                userHasPushToken = true;
                                if (!pushMessages.contains(msg)) {
                                    pushMessages.add(msg);
                                }
                            } else {
                                userHasOTPToken = true;
                                if (!otpMessages.contains(msg)) {
                                    otpMessages.add(msg);
                                }
                            }
                        }
                        if (userHasPushToken) {
                            tokenType = TOKEN_TYPE_PUSH;
                        }
                    }
                } else {
                    logger.error("Trigger challenge response did not contain 'detail'");
                }
            } else {
                logger.error("Trigger challenge response was invalid");
            } */
        }

        // Enroll token if enabled and user does not have one
        String tokenEnrollmentQR = "";
        if (config.doEnrollToken()) {
            //_log.info("Check if token has to be enrolled...");
            // Get the current list of tokens for the user


            List<TokenInfo> tokenInfos = privacyIDEA.getTokenInfo(currentUser);

            if (tokenInfos == null || tokenInfos.isEmpty()) {
                RolloutInfo rolloutInfo = privacyIDEA.tokenRollout(currentUser, config.getEnrollingTokenType());
                tokenEnrollmentQR = rolloutInfo.googleurl.img;
            }

            /*Map<String, String> params = new HashMap<>();
            params.put(PARAM_KEY_USER, currentUser);
            JsonObject body = endpoint.sendRequest(ENDPOINT_TOKEN, params, true, GET);
            if (body != null) {
                JsonObject value = body.getJsonObject(JSON_KEY_RESULT).getJsonObject(JSON_KEY_VALUE);
                tokenCounter = value.getInt(JSON_KEY_COUNT, 0);
                if (tokenCounter < 1) {
                    // User has no tokens - request rollout
                    params = new HashMap<>();
                    params.put(PARAM_KEY_USER, currentUser);
                    params.put(PARAM_KEY_TYPE, config.getEnrollingTokenType());
                    params.put(PARAM_KEY_GENKEY, "1");
                    JsonObject response = endpoint.sendRequest(ENDPOINT_TOKEN_INIT, params, true, POST);
                    if (response != null) {
                        JsonObject detail = response.getJsonObject(JSON_KEY_DETAIL);
                        if (detail != null) {
                            JsonObject googleurl = detail.getJsonObject(JSON_KEY_GOOGLEURL);
                            tokenEnrollmentQR = googleurl.getString(JSON_KEY_IMG);
                        }
                    } else {
                        logger.error("Token info response was empty or malformed!");
                    }
                }
            } */
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
                //log.info("Authentication failed for user " + context.getUser().getUsername());
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

            /*Map<String, String> params = new HashMap<>();
            params.put(PARAM_KEY_TRANSACTION_ID, transactionID);
            JsonObject body = endpoint.sendRequest(ENDPOINT_POLL_TRANSACTION, params, false, GET);
            if (body != null) {
                JsonObject result = body.getJsonObject(JSON_KEY_RESULT);
                if (result != null) {
                    if (result.getBoolean(JSON_KEY_VALUE, false)) {
                        // Finalize the authentication with a call to /validate/check which gives the real success value
                        // https://privacyidea.readthedocs.io/en/latest/configuration/authentication_modes.html#outofband-mode
                        params.clear();
                        params.put(PARAM_KEY_USER, currentUserName);
                        if (transactionID != null && !transactionID.isEmpty()) {
                            params.put(PARAM_KEY_TRANSACTION_ID, transactionID);
                        }
                        params.put(PARAM_KEY_PASS, null);
                        JsonObject response = endpoint.sendRequest(ENDPOINT_VALIDATE_CHECK, params, false, POST);
                        if (response != null) {
                            JsonObject result2 = response.getJsonObject(JSON_KEY_RESULT);
                            return result2.getBoolean(JSON_KEY_VALUE, false);
                        }
                    }
                }
            } else {
                logger.error("Polling response was empty or malformed!");
            }
            return false; */
        }

        String otp = formData.getFirst(Const.FORM_PI_OTP);
        return privacyIDEA.validateCheck(currentUserName, otp).getValue();


        /*Map<String, String> params = new HashMap<>();
        params.put(PARAM_KEY_USER, currentUserName);
        params.put(PARAM_KEY_PASS, otp);
        params.put(PARAM_KEY_REALM, config.getRealm());
        if (config.doTriggerChallenge() && tokenEnrollmentQR.isEmpty()) {
            params.put(PARAM_KEY_TRANSACTION_ID, transactionID);
        }

        JsonObject body = endpoint.sendRequest(ENDPOINT_VALIDATE_CHECK, params, false, POST);
        if (body != null) {
            JsonObject result = body.getJsonObject(JSON_KEY_RESULT);
            return result.getBoolean(JSON_KEY_VALUE, false);
        } else {
            logger.error("Validate check response was empty or malformed!");
        }
        return false; */
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
    }

    @Override
    public void log(String message) {
        logger.info(message);
    }

    @Override
    public void error(String message) {
        logger.error(message);
    }

    @Override
    public void log(Throwable t) {
        logger.info(t);
    }

    @Override
    public void error(Throwable t) {
        logger.error(t);
    }
}
