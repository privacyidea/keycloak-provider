package org.privacyidea.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.*;

import static org.privacyidea.authenticator.Const.*;

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
public class PrivacyIDEAAuthenticator implements org.keycloak.authentication.Authenticator {

    private static Logger _log = Logger.getLogger(PrivacyIDEAAuthenticator.class);

    private Configuration _config;
    private Endpoint _endpoint;

    /**
     * This function will be called when the authentication flow triggers the privacyIDEA execution.
     * i.e. after the username + password have been submitted.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        _config = new Configuration(context.getAuthenticatorConfig().getConfig());
        _endpoint = new Endpoint(_config);

        UserModel user = context.getUser();
        String currentUser = user.getUsername();
        String transactionID = null;
        //Set<GroupModel> groupModelSet = ;
        //GroupModel[] groupModels = groupModelSet.toArray(new GroupModel[0]);

        // Check if privacyIDEA is enabled for the current user
        for (GroupModel groupModel : user.getGroups()) {
            for (String excludedGroup : _config.getExcludedGroups()) {
                if (groupModel.getName().equals(excludedGroup)) {
                    context.success();
                    return;
                }
            }
        }

        // Trigger challenge for current user
        int tokenCounter = 0;
        String tokenType = TOKEN_TYPE_OTP;
        // Check which kinds of tokens the user has to adapt the options of the form
        boolean userHasPushToken = false;
        boolean userHasOTPToken = false;
        // Collect the messages for the tokens to display
        List<String> pushMessages = new ArrayList<>();
        List<String> otpMessages = new ArrayList<>();
        if (_config.doTriggerChallenge()) {
            Map<String, String> params = new HashMap<>();
            params.put(PARAM_KEY_USER, currentUser);
            JsonObject body = _endpoint.sendRequest(ENDPOINT_TRIGGERCHALLENGE, params, true, POST);
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
                    _log.error("Trigger challenge response did not contain 'detail'");
                }
            } else {
                _log.error("Trigger challenge response was invalid");
            }
        }

        // Enroll token if enabled and user does not have one
        String tokenEnrollmentQR = "";
        if (_config.doEnrollToken()) {
            //_log.info("Check if token has to be enrolled...");
            // Get the current list of tokens for the user
            Map<String, String> params = new HashMap<>();
            params.put(PARAM_KEY_USER, currentUser);
            JsonObject body = _endpoint.sendRequest(ENDPOINT_TOKEN, params, true, GET);
            if (body != null) {
                JsonObject value = body.getJsonObject(JSON_KEY_RESULT).getJsonObject(JSON_KEY_VALUE);
                tokenCounter = value.getInt(JSON_KEY_COUNT, 0);
                if (tokenCounter < 1) {
                    // User has no tokens - request rollout
                    params = new HashMap<>();
                    params.put(PARAM_KEY_USER, currentUser);
                    params.put(PARAM_KEY_TYPE, _config.getEnrollingTokenType());
                    params.put(PARAM_KEY_GENKEY, "1");
                    JsonObject response = _endpoint.sendRequest(ENDPOINT_TOKEN_INIT, params, true, POST);
                    if (response != null) {
                        JsonObject detail = response.getJsonObject(JSON_KEY_DETAIL);
                        if (detail != null) {
                            JsonObject googleurl = detail.getJsonObject(JSON_KEY_GOOGLEURL);
                            tokenEnrollmentQR = googleurl.getString(JSON_KEY_IMG);
                        }
                    } else {
                        _log.error("Token info response was empty or malformed!");
                    }
                }
            }
        }
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_AUTH_COUNTER, "0");
        if (transactionID != null && !transactionID.isEmpty()) {
            context.getAuthenticationSession().setAuthNote(AUTH_NOTE_TRANSACTION_ID, transactionID);
        }
        // Create login form
        String pushMessage = Utilities.buildPromptMessage(pushMessages, DEFAULT_PUSH_MESSAGE);
        String otpMessage = Utilities.buildPromptMessage(otpMessages, DEFAULT_OTP_MESSAGE);

        Response challenge = context.form()
                .setAttribute(FORM_PUSHTOKEN_INTERVAL, _config.getPushtokenPollingInterval().get(0))
                .setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                .setAttribute(FORM_TOKENTYPE, tokenType)
                .setAttribute(FORM_PUSHTOKEN, userHasPushToken)
                .setAttribute(FORM_OTPTOKEN, userHasOTPToken)
                .setAttribute(FORM_PUSH_MESSAGE, pushMessage)
                .setAttribute(FORM_OTP_MESSAGE, otpMessage)
                .createForm(FORM_FILE_NAME);
        context.challenge(challenge);
    }

    /**
     * This function will be called if the user submitted the OTP form
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
        String tokenEnrollmentQR = formData.getFirst(FORM_TOKEN_ENROLLMENT_QR);
        String tokenType = formData.getFirst(FORM_TOKENTYPE);
        boolean pushToken = formData.getFirst(FORM_PUSHTOKEN).equals(TRUE);
        boolean otpToken = formData.getFirst(FORM_OTPTOKEN).equals(TRUE);
        String pushMessage = formData.getFirst(FORM_PUSH_MESSAGE);
        String otpMessage = formData.getFirst(FORM_OTP_MESSAGE);
        String tokenTypeChanged = formData.getFirst(FORM_TOKENTYPE_CHANGED);

        if (!validateResponse(context)) {
            int authCounter = Integer.parseInt(context.getAuthenticationSession().getAuthNote(AUTH_NOTE_AUTH_COUNTER)) + 1;
            authCounter = (authCounter >= _config.getPushtokenPollingInterval().size() ? _config.getPushtokenPollingInterval().size() - 1 : authCounter);
            context.getAuthenticationSession().setAuthNote(AUTH_NOTE_AUTH_COUNTER, Integer.toString(authCounter));

            LoginFormsProvider form = context.form()
                    .setAttribute(FORM_PUSHTOKEN_INTERVAL, _config.getPushtokenPollingInterval().get(authCounter))
                    .setAttribute(FORM_TOKEN_ENROLLMENT_QR, tokenEnrollmentQR)
                    .setAttribute(FORM_TOKENTYPE, tokenType)
                    .setAttribute(FORM_PUSHTOKEN, pushToken)
                    .setAttribute(FORM_OTPTOKEN, otpToken)
                    .setAttribute(FORM_PUSH_MESSAGE, pushMessage == null ? DEFAULT_PUSH_MESSAGE : pushMessage)
                    .setAttribute(FORM_OTP_MESSAGE, otpMessage == null ? DEFAULT_OTP_MESSAGE : otpMessage);

            // Dont display the error if the token type was switched
            if (!tokenTypeChanged.equals(TRUE)) {
                form.setError(tokenType.equals(TOKEN_TYPE_PUSH) ? "Authentication not verified yet." : "Authentication failed.");
                //log.info("Authentication failed for user " + context.getUser().getUsername());
            }
            Response challenge = form.createForm(FORM_FILE_NAME);
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
        if (formData.getFirst(FORM_TOKENTYPE_CHANGED).equals(TRUE)) {
            return false;
        }

        // Get data from form
        String tokenEnrollmentQR = formData.getFirst(FORM_TOKEN_ENROLLMENT_QR);
        String tokenType = formData.getFirst(FORM_TOKENTYPE);
        String transactionID = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_TRANSACTION_ID);
        String currentUserName = context.getUser().getUsername();

        if (tokenType.equals(TOKEN_TYPE_PUSH)) {
            Map<String, String> params = new HashMap<>();
            params.put(PARAM_KEY_TRANSACTION_ID, transactionID);
            JsonObject body = _endpoint.sendRequest(ENDPOINT_POLL_TRANSACTION, params, false, GET);
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
                        JsonObject response = _endpoint.sendRequest(ENDPOINT_VALIDATE_CHECK, params, false, POST);
                        if (response != null) {
                            JsonObject result2 = response.getJsonObject(JSON_KEY_RESULT);
                            return result2.getBoolean(JSON_KEY_VALUE, false);
                        }
                    }
                }
            } else {
                _log.error("Polling response was empty or malformed!");
            }
            return false;
        }

        String otp = formData.getFirst(FORM_PI_OTP);
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_KEY_USER, currentUserName);
        params.put(PARAM_KEY_PASS, otp);
        params.put(PARAM_KEY_REALM, _config.getRealm());
        if (_config.doTriggerChallenge() && tokenEnrollmentQR.isEmpty()) {
            params.put(PARAM_KEY_TRANSACTION_ID, transactionID);
        }

        JsonObject body = _endpoint.sendRequest(ENDPOINT_VALIDATE_CHECK, params, false, POST);
        if (body != null) {
            JsonObject result = body.getJsonObject(JSON_KEY_RESULT);
            return result.getBoolean(JSON_KEY_VALUE, false);
        } else {
            _log.error("Validate check response was empty or malformed!");
        }
        return false;
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
}
