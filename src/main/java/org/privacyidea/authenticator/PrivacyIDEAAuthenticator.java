/*
 * Copyright 2023 NetKnights GmbH - micha.preusser@netknights.it
 * Copyright 2025 NetKnights GmbH - nils.behlen@netknights.it
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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Map;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.common.Version;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;
import org.privacyidea.AuthenticationStatus;
import org.privacyidea.ChallengeStatus;
import org.privacyidea.IPILogger;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;

import static org.privacyidea.PIConstants.AUTH_FORM;
import static org.privacyidea.PIConstants.AUTH_FORM_RESULT;
import static org.privacyidea.PIConstants.PASSWORD;
import static org.privacyidea.PIConstants.USERNAME;
import static org.privacyidea.authenticator.Const.FORM_FILE_NAME;
import static org.privacyidea.authenticator.Const.FORM_OTP;
import static org.privacyidea.authenticator.Const.NOTE_COUNTER;
import static org.privacyidea.authenticator.Const.NOTE_OTP_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_PASSKEY_REGISTRATION_SERIAL;
import static org.privacyidea.authenticator.Const.NOTE_PASSKEY_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_PUSH_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_WEBAUTHN_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.PLUGIN_USER_AGENT;

public class PrivacyIDEAAuthenticator implements org.keycloak.authentication.Authenticator, IPILogger
{
    private final Logger logger = Logger.getLogger(PrivacyIDEAAuthenticator.class);
    private final Util util;
    private final ConcurrentHashMap<String, Pair> piInstanceMap = new ConcurrentHashMap<>();
    private final Gson gson = new Gson();
    private boolean logEnabled = false;

    public PrivacyIDEAAuthenticator()
    {
        log("PrivacyIDEA Authenticator initialized.");
        this.util = new Util(this);
    }

    /**
     * Decodes a JWT and returns its payload as a map of claims.
     * This method does not verify the signature.
     *
     * @param jwtString The JWT as a string.
     * @return A map of the claims from the JWT payload, or an empty map if decoding fails.
     */
    private Map<String, String> decodeJWT(String jwtString)
    {
        if (StringUtil.isBlank(jwtString))
        {
            return Collections.emptyMap();
        }
        try
        {
            JWSInput jwsInput = new JWSInput(jwtString);
            String payload = new String(jwsInput.getContent(), StandardCharsets.UTF_8);

            Type type = new TypeToken<Map<String, Object>>()
            {
            }.getType();
            Map<String, Object> claims = gson.fromJson(payload, type);

            // Convert all values to String to match the method signature and avoid class cast exceptions.
            return claims.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> String.valueOf(entry.getValue())));
        }
        catch (Exception e)
        {
            error("Failed to decode JWT: " + e.getMessage());
            return Collections.emptyMap();
        }
    }


    /**
     * Create new instances of PrivacyIDEA and the Configuration, if it does not exist yet.
     * Also adds them to the instance map.
     *
     * @param context for authentication flow
     */
    private Pair loadConfiguration(final AuthenticationFlowContext context)
    {
        // Get the configuration and privacyIDEA instance for the current realm
        // If none is found or the configuration has changed, create a new one
        final String kcRealm = context.getRealm().getName();
        final Pair currentPair = piInstanceMap.get(kcRealm);
        final int incomingHash = context.getAuthenticatorConfig().getConfig().hashCode();
        if (currentPair == null || incomingHash != currentPair.configuration().configHash())
        {
            log("Creating new privacyIDEA instance for realm " + kcRealm);
            final Map<String, String> configMap = context.getAuthenticatorConfig().getConfig();
            Configuration config = new Configuration(configMap);
            String kcVersion = Version.VERSION;
            String providerVersion = PrivacyIDEAAuthenticator.class.getPackage().getImplementationVersion();
            String fullUserAgent = PLUGIN_USER_AGENT + "/" + providerVersion + " Keycloak/" + kcVersion;
            PrivacyIDEA privacyIDEA = PrivacyIDEA.newBuilder(config.serverURL(), fullUserAgent)
                                                 .verifySSL(config.sslVerify())
                                                 .logger(this)
                                                 .realm(config.realm())
                                                 .serviceAccount(config.serviceAccountName(), config.serviceAccountPass())
                                                 .serviceRealm(config.serviceAccountRealm())
                                                 .httpTimeoutMs(config.httpTimeoutMs())
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
     * This function is called when the authentication flow triggers the privacyIDEA execution.
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
        AuthenticationForm piForm = new AuthenticationForm(config);
        piForm.setPollInterval(config.pollingInterval().get(0));
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        log("--- Form Data Authenticate ---");
        formData.forEach((key, values) -> log(key + "=" + values));

        // Check for an openid from entraid request first
        String usernameFromOpenId = "";
        if (formData.containsKey("scope"))
        {
            String scope = formData.getFirst("scope");
            if (scope.equals("openid"))
            {
                log("openid request!");
                AuthenticationSessionModel session = context.getAuthenticationSession();
                for (Map.Entry<String, List<String>> entry : formData.entrySet())
                {
                    String key = entry.getKey();
                    List<String> values = entry.getValue();

                    if ("id_token_hint".equals(key))
                    {
                        String t = values.getFirst();
                        log("ID TOKEN HINT:");
                        Map<String, String> token = decodeJWT(t);
                        if (!token.containsKey("preferred_username"))
                        {
                            error("Openid request: Missing 'preferred_username' parameter!");
                            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                            return;
                        }

                        for (Map.Entry<String, String> tokenEntry : token.entrySet())
                        {
                            String k = tokenEntry.getKey();
                            String v = tokenEntry.getValue();
                            logger.infof("%s = %s", k, v);
                            if ("preferred_username".equals(k))
                            {
                                usernameFromOpenId = v;
                            }
                            session.setAuthNote(k, v);
                        }
                    }
                    else
                    {
                        session.setAuthNote(key, values.toString());
                        logger.infof("Added AuthNote Key: %s, Value: %s", key, session.getAuthNote(key));
                    }
                }
                // Check if the user is present in keycloak. If not, the authentication can not be completed.
                UserModel userModel = context.getSession().users().getUserByUsername(context.getRealm(), usernameFromOpenId);
                if (userModel == null)
                {
                    error("User " + usernameFromOpenId + " not found in realm " + context.getRealm().getName());
                    context.failure(AuthenticationFlowError.UNKNOWN_USER);
                    return;
                }
                context.clearUser();
                context.setUser(userModel);
            }
        }

        // Check if a user is already present.
        // If no user is present, request it. Optionally request the password if not disabled.
        UserModel user = context.getUser();
        if (user == null)
        {
            context.clearUser();
            piForm.setMode(config.isDisablePasswordCheck() ? Mode.USERNAME : Mode.USERNAMEPASSWORD);
        }
        else
        {
            // Check if the current user is member of an included or excluded group
            boolean noMFAbyGroup = util.checkMFAExcludedByGroup(config, user);
            if (noMFAbyGroup)
            {
                context.success();
                return;
            }
        }
        String currentPassword = null;
        // In some cases, there will be no FormParameters so check if it is even possible to get the password
        if (config.sendPassword() && context.getHttpRequest() != null && context.getHttpRequest().getDecodedFormParameters() != null &&
            context.getHttpRequest().getDecodedFormParameters().get(PASSWORD) != null)
        {
            currentPassword = context.getHttpRequest().getDecodedFormParameters().get(PASSWORD).get(0);
        }

        Map<String, String> headers = util.getHeaders(context, config);

        // Trigger challenges if configured. If not, the function does nothing
        if (user != null)
        {
            PIResponse response = util.tryTriggerFirstStep(user.getUsername(), privacyIDEA, config, currentPassword,
                                                           util.getAdditionalParamsFromContext(context, config), headers);
            if (response != null)
            {
                if (response.authenticationSuccessful())
                {
                    context.success();
                    return;
                }
                piForm = util.evaluateResponse(response, context, piForm, config);
            }
        }

        // Prepare the form and auth notes to pass infos to the UI and the next step
        context.getAuthenticationSession().setAuthNote(NOTE_COUNTER, "0");
        context.form().setAttribute(AUTH_FORM, piForm);
        Response responseForm = context.form().createForm(FORM_FILE_NAME);

        context.challenge(responseForm);
    }

    /**
     * This function is called when the privacyIDEA form is submitted.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void action(AuthenticationFlowContext context)
    {
        // Get the configuration and privacyIDEA instance for the current realm
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

        // Check for cancel
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel"))
        {
            context.resetFlow();
            return;
        }
        // Get the data from the forms and session
        LoginFormsProvider kcForm = context.form();

        log("--- Form Data Action ---");
        formData.forEach((key, values) -> log(key + "=" + values));

        // AuthenticationFormResult
        if (!formData.containsKey(AUTH_FORM_RESULT))
        {
            logger.error("No authenticationFormResult found in form data!");
            return;
        }
        String t = formData.getFirst(AUTH_FORM_RESULT);
        AuthenticationFormResult piFormResult = AuthenticationFormResult.fromJson(t);
        if (piFormResult == null)
        {
            logger.error("AuthenticationFormResult could not be parsed: " + t);
            return;
        }
        // AuthenticationForm
        if (!formData.containsKey(AUTH_FORM))
        {
            logger.error("No authenticationForm found in form data!");
            return;
        }
        t = formData.getFirst(AUTH_FORM);
        AuthenticationForm piForm = AuthenticationForm.fromJson(t);
        if (piForm == null)
        {
            logger.error("AuthenticationForm could not be parsed: " + t);
            return;
        }
        //logger.error("PiForm: " + piForm);
        //logger.error("PiFormResult: " + piFormResult);
        // Reset requested: reset the flow
        if (piFormResult.authenticationResetRequested)
        {
            context.resetFlow();
            return;
        }
        piForm.setAutoSubmitLength(config.otpLength());
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

        String otpTransactionId = "";
        String pushTransactionId = "";
        String webAuthnTransactionId = "";
        if (authenticationSession != null)
        {
            otpTransactionId = context.getAuthenticationSession().getAuthNote(NOTE_OTP_TRANSACTION_ID);
            pushTransactionId = context.getAuthenticationSession().getAuthNote(NOTE_PUSH_TRANSACTION_ID);
            webAuthnTransactionId = context.getAuthenticationSession().getAuthNote(NOTE_WEBAUTHN_TRANSACTION_ID);
        }
        else
        {
            error("AuthenticationSession is null, unable to get TRANSACTION_IDs");
        }

        Map<String, String> headers = util.getHeaders(context, config);
        kcForm.setAttribute(AUTH_FORM, piForm);

        boolean didTrigger = false;
        PIResponse response = null;

        // Passkey: Will return the username and end the authentication on success. This is different from the WebAuthn authentication
        // Which is attempted later.
        if (StringUtil.isNotBlank(piFormResult.passkeySignResponse))
        {
            if (StringUtil.isBlank(piFormResult.origin))
            {
                logger.error("Origin is missing for WebAuthn authentication!");
            }
            else
            {
                String passkeyTransactionID = "";
                if (authenticationSession != null)
                {
                    passkeyTransactionID = authenticationSession.getAuthNote(NOTE_PASSKEY_TRANSACTION_ID);
                }
                else
                {
                    error("AuthenticationSession is null, unable to get PASSKEY_TRANSACTION_ID");
                }

                response = privacyIDEA.validateCheckPasskey(passkeyTransactionID, piFormResult.passkeySignResponse, piFormResult.origin,
                                                            headers);
                if (response != null)
                {
                    if (response.authenticationSuccessful())
                    {
                        if (StringUtil.isNotBlank(response.username))
                        {
                            context.clearUser();
                            UserModel userModel = context.getSession().users().getUserByUsername(context.getRealm(), response.username);
                            if (userModel == null)
                            {
                                error("User " + response.username + " not found in realm " + context.getRealm().getName());
                                kcForm.setError("User not found!");
                                Response responseForm = kcForm.createForm(FORM_FILE_NAME);
                                context.challenge(responseForm);
                                return;
                            }
                            context.setUser(userModel);
                        }
                        if (context.getUser() == null)
                        {
                            error("No user set after passkey authentication!");
                            context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
                            return;
                        }
                        context.success();
                        // TODO this needs to be evaluated in the ProtocolMapper and is not complete/working yet
                        log("Setting privacyidea_authentication_method to fido2");
                        context.getAuthenticationSession().setAuthNote("privacyidea_authentication_method", "fido2");
                        context.getAuthenticationSession().getUserSessionNotes().put("privacyidea_authentication_method", "fido2");
                    }
                    else
                    {
                        piForm.setErrorMessage("passkey_authentication_failed");
                        kcForm.setAttribute(AUTH_FORM, piForm);
                        Response responseForm = kcForm.createForm(FORM_FILE_NAME);
                        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, responseForm);
                    }
                    return;
                }
            }
        }
        // Passkey login requested: Get a challenge and return
        if (piFormResult.passkeyLoginRequested)
        {
            PIResponse passkeyResponse = privacyIDEA.validateInitialize("passkey");
            if (passkeyResponse != null && StringUtil.isNotBlank(passkeyResponse.passkeyChallenge))
            {
                piForm.setPasskeyChallenge(passkeyResponse.passkeyChallenge);
                piForm.setMode(Mode.PASSKEY);
                kcForm.setAttribute(AUTH_FORM, piForm);
                context.getAuthenticationSession().setAuthNote(NOTE_PASSKEY_TRANSACTION_ID, passkeyResponse.transactionID);
                Response responseForm = kcForm.createForm(FORM_FILE_NAME);
                context.challenge(responseForm);
                return;
            }
        }
        // Passkey login cancelled: Remove the challenge and transaction ID
        if (piFormResult.passkeyLoginCancelled)
        {
            piForm.setPasskeyChallenge("");
            context.getAuthenticationSession().removeAuthNote(NOTE_PASSKEY_TRANSACTION_ID);
        }
        // Passkey registration: enroll_via_multichallenge, this is after successful authentication
        if (StringUtil.isNotBlank(piFormResult.passkeyRegistrationResponse))
        {
            String serial = "";
            String transactionId = "";
            if (authenticationSession != null)
            {
                serial = context.getAuthenticationSession().getAuthNote(NOTE_PASSKEY_REGISTRATION_SERIAL);
                transactionId = context.getAuthenticationSession().getAuthNote(NOTE_PASSKEY_TRANSACTION_ID);
            }
            else
            {
                error("AuthenticationSession is null, unable to get PASSKEY_REGISTRATION_SERIAL and PASSKEY_TRANSACTION_ID");
            }
            PIResponse passkeyResponse = privacyIDEA.validateCheckCompletePasskeyRegistration(transactionId, serial,
                                                                                              context.getUser().getUsername(),
                                                                                              piFormResult.passkeyRegistrationResponse,
                                                                                              piFormResult.origin, headers);
            if (passkeyResponse != null && passkeyResponse.value)
            {
                context.success();
                return;
            }
            else if (passkeyResponse != null && passkeyResponse.error != null)
            {
                kcForm.setError(passkeyResponse.error.message);
                kcForm.setAttribute(AUTH_FORM, piForm);
                Response responseForm = kcForm.createForm(FORM_FILE_NAME);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, responseForm);
                return;
            }
        }

        // Set the user and verify the password, check if MFA is required for the user
        boolean userRequested = piForm.getMode() == Mode.USERNAMEPASSWORD || piForm.getMode() == Mode.USERNAME;
        if (userRequested)
        {
            String username = formData.getFirst(USERNAME);

            if (StringUtil.isBlank(username))
            {
                logger.error("Username was requested but has not been provided!");
                kcForm.setError("Username is required!");
                kcForm.setAttribute(AUTH_FORM, piForm);
                Response responseForm = kcForm.createForm(FORM_FILE_NAME);
                context.challenge(responseForm);
                return;
            }
            UserModel userModel = context.getSession().users().getUserByUsername(context.getRealm(), username);
            if (userModel == null)
            {
                logger.error("User " + username + " not found in realm " + context.getRealm().getName());
                kcForm.setError("Invalid Credentials!");
                kcForm.setAttribute(AUTH_FORM, piForm);
                Response responseForm = kcForm.createForm(FORM_FILE_NAME);
                context.challenge(responseForm);
                return;
            }
            if (!config.isDisablePasswordCheck())
            {
                String password = formData.getFirst(PASSWORD);
                boolean passwordCorrect = userModel.credentialManager().isValid(UserCredentialModel.password(password));
                if (!passwordCorrect)
                {
                    logger.debug("User " + username + " tried to authenticate with a wrong password.");
                    kcForm.setError("Invalid Credentials!");
                    kcForm.setAttribute(AUTH_FORM, piForm);
                    Response responseForm = kcForm.createForm(FORM_FILE_NAME);
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, responseForm);
                    return;
                }
            }
            context.clearUser();
            context.setUser(userModel);

            // Now that we have a user, we can check if MFA is required for the user's groups
            boolean mfaExcludedByGroup = util.checkMFAExcludedByGroup(config, userModel);
            if (mfaExcludedByGroup)
            {
                context.success();
                return;
            }
        }

        // OTP / Push / WebAuthn: User has to be present by now
        if (context.getUser() == null)
        {
            logger.error("User is not available in the context!");
            context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
            return;
        }
        String currentUsername = context.getUser().getUsername();
        Mode currentMode = piFormResult.modeChanged ? piFormResult.newMode : piForm.getMode();
        piForm.setMode(currentMode);
        kcForm.setAttribute(AUTH_FORM, piForm);
        boolean fido2Used = false;

        // Send a request to privacyIDEA depending on the mode. Evaluation of the response is done afterward independently of the mode.
        if (Mode.PUSH.equals(currentMode))
        {
            // In push mode, poll for the transaction id to see if the challenge has been answered
            ChallengeStatus pollTransactionStatus = privacyIDEA.pollTransaction(pushTransactionId);
            if (pollTransactionStatus == ChallengeStatus.accept)
            {
                // If the challenge has been answered, finalize with a call to validate check
                response = privacyIDEA.validateCheck(currentUsername, "", pushTransactionId,
                                                     util.getAdditionalParamsFromContext(context, config), headers);
            }
            else if (pollTransactionStatus == ChallengeStatus.declined)
            {
                // If challenge has been declined, show the error message
                log("Push Authentication declined by the user.");
                context.cancelLogin();
            }
            else if (pollTransactionStatus != ChallengeStatus.pending)
            {
                // If poll transaction failed, show the error message and fallback to otp mode.
                kcForm.setError("Push authentication failed. Please use a different token or restart the login.");
                piForm.setMode(Mode.OTP);
            }
        }
        else if (StringUtil.isNotBlank(piFormResult.webAuthnSignResponse))
        {
            if (StringUtil.isBlank(piFormResult.origin))
            {
                logger.error("Origin is missing for WebAuthn authentication!");
            }
            else
            {
                response = privacyIDEA.validateCheckWebAuthn(currentUsername, webAuthnTransactionId, piFormResult.webAuthnSignResponse,
                                                             piFormResult.origin, util.getAdditionalParamsFromContext(context, config),
                                                             headers);
                fido2Used = true;
            }
        }
        else if (Mode.USERNAMEPASSWORD.equals(currentMode) || Mode.USERNAME.equals(currentMode))
        {
            String password = formData.getFirst(PASSWORD);
            response = util.tryTriggerFirstStep(currentUsername, privacyIDEA, config, password,
                                                util.getAdditionalParamsFromContext(context, config), headers);
        }
        else if (!piFormResult.modeChanged)
        {
            // /validate/check with the OTP input
            response = privacyIDEA.validateCheck(currentUsername, formData.getFirst(FORM_OTP), otpTransactionId,
                                                 util.getAdditionalParamsFromContext(context, config), headers);
        }

        // Evaluate the response: Check for success, error or new challenges
        if (response != null)
        {
            if (response.authenticationSuccessful())
            {
                context.success();
                if (fido2Used)
                {
                    // TODO this needs to be evaluated in the ProtocolMapper and is not complete/working yet
                    log("Setting privacyidea_authentication_method to fido2");
                    context.getAuthenticationSession().setAuthNote("privacyidea_authentication_method", "fido2");
                    context.getAuthenticationSession().getUserSessionNotes().put("privacyidea_authentication_method", "fido2");
                }
                return;
            }
            if (response.error != null)
            {
                kcForm.setError(response.error.message);
                context.failureChallenge(AuthenticationFlowError.INVALID_USER, kcForm.createForm(FORM_FILE_NAME));
                return;
            }
            piForm = util.evaluateResponse(response, context, piForm, config);
            didTrigger = piForm.isChallengesTriggered();
        }

        // The authCounter is also used to determine the polling interval for push
        // If the authCounter is bigger than the size of the polling interval list, repeat the last value in the list
        int authCounter = 0;
        if (authenticationSession != null)
        {
            authCounter = Integer.parseInt(context.getAuthenticationSession().getAuthNote(NOTE_COUNTER)) + 1;
        }
        else
        {
            error("AuthenticationSession is null, unable to get AUTH_COUNTER");
        }

        authCounter = (authCounter >= config.pollingInterval().size() ? config.pollingInterval().size() - 1 : authCounter);
        context.getAuthenticationSession().setAuthNote(NOTE_COUNTER, Integer.toString(authCounter));
        piForm.setPollInterval(config.pollingInterval().get(authCounter));

        // Prepare form for the next step, depending on what to do next
        kcForm.setAttribute(AUTH_FORM, piForm);
        String authenticationFailureMessage = "Authentication failed.";
        if ((piFormResult.modeChanged && !didTrigger) ||
            Mode.PUSH.equals(currentMode) && (response != null && StringUtil.isBlank(response.passkeyRegistration)))
        {
            if (Mode.PUSH.equals(currentMode))
            {
                piForm.setErrorMessage("push_auth_not_verified");
            }
            context.challenge(kcForm.createForm(FORM_FILE_NAME));
        }
        else if (currentMode == Mode.USERNAMEPASSWORD || currentMode == Mode.USERNAME)
        {
            // Continue with 2nd step (second factor)
            // If there is no next Mode set yet, because no challenges were triggered, or it was not attempted, just continue with OTP
            final Mode nextMode = piForm.getMode();
            if (nextMode == Mode.USERNAMEPASSWORD || nextMode == Mode.USERNAME)
            {
                piForm.setMode(Mode.OTP);
            }
            kcForm.setAttribute(AUTH_FORM, piForm);
            context.challenge(kcForm.createForm(FORM_FILE_NAME));
        }
        else if (response != null && StringUtil.isNotBlank(response.passkeyRegistration))
        {
            kcForm.setError(response.message);
            context.challenge(kcForm.createForm(FORM_FILE_NAME));
        }
        else
        {
            // Fail
            if (currentMode.equals(Mode.PUSH))
            {
                piForm.setErrorMessage("push_auth_not_verified");
                context.challenge(kcForm.createForm(FORM_FILE_NAME));
            }
            else if (!didTrigger)
            {
                kcForm.setError(authenticationFailureMessage);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, kcForm.createForm(FORM_FILE_NAME));
            }
            // Check failed auth vs real error
            else if (response.error != null)
            {
                piForm.setErrorMessage(response.error.message);
                kcForm.setError(response.error.message);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, kcForm.createForm(FORM_FILE_NAME));
            }
            else if (response.authentication.equals(AuthenticationStatus.REJECT))
            {
                kcForm.setError(response.message);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, kcForm.createForm(FORM_FILE_NAME));
            }
            else
            {
                context.challenge(kcForm.createForm(FORM_FILE_NAME));
            }
        }
    }

    @Override
    public boolean requiresUser()
    {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user)
    {
        //log("Configured for realm " + realm.getName());
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user)
    {
        //log("Setting required actions for realm " + realm.getName() + " and user " + user.getUsername());
    }

    @Override
    public void close()
    {
        //log("Closing PrivacyIDEA Authenticator.");
    }

    // IPILogger implementation
    @Override
    public void log(String message)
    {
        if (logEnabled)
        {
            logger.info(message);
        }
    }

    @Override
    public void error(String message)
    {
        if (logEnabled)
        {
            logger.error(message);
        }
    }

    @Override
    public void log(Throwable t)
    {
        if (logEnabled)
        {
            logger.info(t);
        }
    }

    @Override
    public void error(Throwable t)
    {
        if (logEnabled)
        {
            logger.error(t);
        }
    }
}