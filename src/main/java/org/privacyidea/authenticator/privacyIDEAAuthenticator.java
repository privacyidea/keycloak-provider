package org.privacyidea.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.*;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Copyright 2019 NetKnights GmbH - micha.preusser@neknights.it
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
public class privacyIDEAAuthenticator implements Authenticator {
    public static final String CREDENTIAL_TYPE = "pi_otp";

    private static Logger log = Logger.getLogger(privacyIDEAAuthenticator.class);

    private String _serverURL;
    private String _realm;
    private boolean _doSSLVerify;
    private boolean _doTriggerChallenge;
    private String _serviceAccountName;
    private String _serviceAccountPass;
    private List<String> _excludedGroups = new ArrayList<>();
    private boolean _doEnrollToken;
    private String _enrollingTokenType;
    private List<Integer> _pushtokenPollingInterval = new ArrayList<>();
    private String _serviceAccountAuthToken;

    /**
     * This function will be called when the authentication flow triggers the privacyIDEA execution.
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        //log.debug("authenticate");
        String username;
        String tokenEnrollmentQR = "";
        String tokenType = "otp";
        boolean pushToken = false;
        boolean otpToken = false;
        StringBuilder pushMessageSB = null;
        StringBuilder otpMessageSB = null;

        UserModel user = context.getUser();
        username = user.getUsername();

        Set<GroupModel> groupModelSet = user.getGroups();
        GroupModel[] groupModels = groupModelSet.toArray(new GroupModel[0]);

        AuthenticatorConfigModel acm = context.getAuthenticatorConfig();

        loadConfiguration(acm.getConfig());

        // Check if privacyIDEA is enabled for the current user
        for (GroupModel groupModel : groupModels) {
            for (String excludedGroup : _excludedGroups) {
                if (groupModel.getName().equals(excludedGroup)) {
                    context.success();
                    return;
                }
            }
        }

        int tokenCounter = 0;

        // Trigger challenge for current user
        if (_doTriggerChallenge) {
            Map<String, String> params = new HashMap<>();
            params.put("username", _serviceAccountName);
            params.put("password", _serviceAccountPass);
            JsonObject body = send("/auth", params, null, "POST");
            try {
                JsonObject result = body.getJsonObject("result");
                JsonObject value = result.getJsonObject("value");
                _serviceAccountAuthToken = value.getString("token");
            } catch (Exception e) {
                log.error(e);
                log.error("Failed to get authorization token.");
                log.error("Unable to read response from privacyIDEA.");
            }

            params.put("user", username);
            body = send("/validate/triggerchallenge", params, _serviceAccountAuthToken, "POST");

            try {
                JsonObject detail = body.getJsonObject("detail");
                JsonObject result = body.getJsonObject("result");
                tokenCounter = result.getInt("value");
                if (tokenCounter > 0) {
                    context.getAuthenticationSession().setAuthNote("pi.transaction_id", detail.getString("transaction_id"));
                    JsonArray multi_challenge = detail.getJsonArray("multi_challenge");
                    for (int i = 0; i < multi_challenge.size(); i++) {
                        JsonObject challenge = multi_challenge.getJsonObject(i);
                        if (challenge.getString("type").equals("push")) {
                            pushToken = true;
                            if (pushMessageSB == null) { // First time
                                pushMessageSB = new StringBuilder().append(challenge.getString("message"));
                            } else { // >1 times
                                pushMessageSB.append(", ").append(challenge.getString("message"));
                            }
                        } else {
                            otpToken = true;
                            if (otpMessageSB == null) { // First time
                                otpMessageSB = new StringBuilder().append(challenge.getString("message"));
                            } else { // >1 times
                                otpMessageSB.append(", ").append(challenge.getString("message"));
                            }
                        }
                    }
                    if (pushToken) {
                        tokenType = "push";
                    }
                }
            } catch (Exception e) {
                log.error(e);
                log.error("Trigger challenge was not successful.");
            }

            // Enroll token if enabled and user does not have one
            if (_doEnrollToken && tokenCounter == 0) {
                params.put("user", username);
                params.put("type", _enrollingTokenType);
                params.put("genkey", "1");
                body = send("/token/init", params, _serviceAccountAuthToken, "POST");
                try {
                    JsonObject detail = body.getJsonObject("detail");
                    JsonObject googleurl = detail.getJsonObject("googleurl");
                    tokenEnrollmentQR = googleurl.getString("img");
                } catch (Exception e) {
                    log.error("Token enrollment failed");
                }
            }
        }

        context.getAuthenticationSession().setAuthNote("authCounter", "0");

        // Create login form
        Response challenge = context.form()
                .setAttribute("pushTokenInterval", _pushtokenPollingInterval.get(0))
                .setAttribute("tokenEnrollmentQR", tokenEnrollmentQR)
                .setAttribute("tokenType", tokenType)
                .setAttribute("pushToken", pushToken)
                .setAttribute("otpToken", otpToken)
                .setAttribute("pushMessage", pushMessageSB == null ? "" : pushMessageSB.toString())
                .setAttribute("otpMessage", otpMessageSB == null ? "Please enter OTP" : otpMessageSB.toString())
                .createForm("privacyIDEA.ftl");
        context.challenge(challenge);
    }

    private void loadConfiguration(Map<String, String> configMap) {
        _serverURL = configMap.get("piserver");
        _realm = configMap.get("pirealm") == null ? "" : configMap.get("pirealm");
        _doSSLVerify = configMap.get("piverifyssl") != null && configMap.get("piverifyssl").equals("true");
        _doTriggerChallenge = configMap.get("pidotriggerchallenge") != null && configMap.get("pidotriggerchallenge").equals("true");
        _serviceAccountName = configMap.get("piserviceaccount") == null ? "" : configMap.get("piserviceaccount");
        _serviceAccountPass = configMap.get("piservicepass") == null ? "" : configMap.get("piservicepass");
        _doEnrollToken = configMap.get("pienrolltoken") != null && configMap.get("pienrolltoken").equals("true");
        _enrollingTokenType = configMap.get("pienrolltokentype") == null ? "" : configMap.get("pienrolltokentype");

        String excludedGroupsStr = configMap.get("piexcludegroups");
        if (excludedGroupsStr != null) {
            _excludedGroups.addAll(Arrays.asList(excludedGroupsStr.split(",")));
        }

        // Set default, overwrite if configured
        _pushtokenPollingInterval.addAll(Arrays.asList(5, 1, 1, 1, 2, 3));
        String s = configMap.get("pipushtokeninterval");
        if (s != null) {
            List<String> strPollingIntervals = Arrays.asList(s.split(","));
            if (!strPollingIntervals.isEmpty()) {
                _pushtokenPollingInterval.clear();
                for (String str : strPollingIntervals) {
                    try {
                        _pushtokenPollingInterval.add(Integer.parseInt(str));
                    } catch (NumberFormatException e) {
                        _pushtokenPollingInterval.add(3); // TODO
                    }
                }
            }
        }
    }

    /**
     * This function will be called if the user submitted the form
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

        // Get data from form
        String tokenEnrollmentQR = formData.getFirst("tokenEnrollmentQR");
        String tokenType = formData.getFirst("tokenType");
        boolean pushToken = formData.getFirst("pushToken").equals("true");
        boolean otpToken = formData.getFirst("otpToken").equals("true");
        String transaction_id = context.getAuthenticationSession().getAuthNote("pi.transaction_id");
        String pushMessage = formData.getFirst("pushMessage");
        String otpMessage = formData.getFirst("otpMessage");
        String tokenTypeChanged = formData.getFirst("tokenTypeChanged");

        if (!validateAnswer(context)) {
            int authCounter = Integer.parseInt(context.getAuthenticationSession().getAuthNote("authCounter")) + 1;
            authCounter = (authCounter >= _pushtokenPollingInterval.size() ? _pushtokenPollingInterval.size() - 1 : authCounter);
            context.getAuthenticationSession().setAuthNote("authCounter", Integer.toString(authCounter));

            LoginFormsProvider form = context.form()
                    .setAttribute("pushTokenInterval", _pushtokenPollingInterval.get(authCounter))
                    .setAttribute("tokenEnrollmentQR", tokenEnrollmentQR)
                    .setAttribute("tokenType", tokenType)
                    .setAttribute("pushToken", pushToken)
                    .setAttribute("otpToken", otpToken)
                    .setAttribute("pushMessage", pushMessage == null ? "" : pushMessage)
                    .setAttribute("otpMessage", otpMessage == null ? "" : otpMessage);

            if (!tokenType.equals("push") || !tokenTypeChanged.equals("true")) {
                form.setError("Authentication failed.");
                log.debug("Authentication failed for user " + context.getUser().getUsername());
            }
            Response challenge = form.createForm("privacyIDEA.ftl");
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
    private boolean validateAnswer(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        UserModel user = context.getUser();
        String username = user.getUsername();

        // Get data from form
        String tokenEnrollmentQR = formData.getFirst("tokenEnrollmentQR");
        String tokenType = formData.getFirst("tokenType");
        boolean pushToken = formData.getFirst("pushToken").equals("true");
        boolean otpToken = formData.getFirst("otpToken").equals("true");
        String transaction_id = context.getAuthenticationSession().getAuthNote("pi.transaction_id");
        String pushMessage = formData.getFirst("pushMessage");
        String otpMessage = formData.getFirst("otpMessage");

        if (formData.getFirst("tokenTypeChanged").equals("true")) {
            return false;
        }

        if (tokenType.equals("push")) {
            Map<String, String> params = new HashMap<>();
            params.put("transaction_id", transaction_id);
            JsonObject body = send("/token/challenges/", params, _serviceAccountAuthToken, "GET");
            try {
                JsonObject result = body.getJsonObject("result");
                JsonObject value = result.getJsonObject("value");
                JsonArray challenges = value.getJsonArray("challenges");
                for (int i = 0; i < challenges.size(); i++) {
                    JsonObject challenge = challenges.getJsonObject(i);
                    if (challenge.getBoolean("otp_valid")) {
                        return true;
                    }
                }
            } catch (Exception e) {
                log.error("Push token verification failed.");
            }
            return false;
        }

        String otp = formData.getFirst("pi_otp");
        Map<String, String> params = new HashMap<>();
        params.put("user", username);
        params.put("pass", otp);
        params.put("realm", _realm);
        if (_doTriggerChallenge && tokenEnrollmentQR.equals("")) {
            params.put("transaction_id", transaction_id);
        }
        JsonObject body = send("/validate/check", params, null, "POST");
        try {
            JsonObject result = body.getJsonObject("result");
            return result.getBoolean("value");
        } catch (Exception e) {
            log.error("Verification was not successful: Invalid response from privacyIDEA");
        }
        return false;
    }

    /**
     * Make a http(s) call to the specified path, the URL is taken from the config.
     * If SSL Verification is turned off in the config, the endpoints certificate will not be verified.
     *
     * @param path      Path to the API endpoint
     * @param params    All necessary parameters for request
     * @param authToken The auth token for the service account (null, if not necessary)
     * @param method    "POST" or "GET"
     * @return JsonObject body which contains the whole response
     */
    private JsonObject send(String path, Map<String, String> params, String authToken, String method) {
        StringBuilder paramsSB = new StringBuilder();
        params.forEach((key, value) -> {
            try {
                paramsSB.append(key).append("=").append(URLEncoder.encode(value, StandardCharsets.UTF_8.toString())).append("&");
            } catch (Exception e) {
                log.error(e);
            }
        });
        paramsSB.deleteCharAt(paramsSB.length() - 1);
        try {
            URL piserverurl;
            if (method.equals("GET")) {
                piserverurl = new URL(_serverURL + path + "?" + paramsSB.toString());
            } else {
                piserverurl = new URL(_serverURL + path);
            }

            HttpURLConnection con;
            if (piserverurl.getProtocol().equals("https")) {
                con = (HttpsURLConnection) (piserverurl.openConnection());
            } else {
                con = (HttpURLConnection) (piserverurl.openConnection());
            }

            if (!_doSSLVerify && con instanceof HttpsURLConnection) {
                con = turnOffSSLVerification((HttpsURLConnection) con);
            }

            con.setDoOutput(true);
            con.setRequestMethod(method);
            if (authToken != null) {
                con.setRequestProperty("Authorization", authToken);
            }
            con.connect();

            if (method.equals("POST")) {
                byte[] outputBytes = (paramsSB.toString()).getBytes(StandardCharsets.UTF_8);
                OutputStream os = con.getOutputStream();
                os.write(outputBytes);
                os.close();
            }

            String response;
            try (InputStream is = con.getInputStream()) {
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                response = br.lines().reduce("", (a, s) -> a += s);
            }
            log.info("RESPONSE: " + response);
            JsonReader jsonReader = Json.createReader(new StringReader(response));
            JsonObject body = jsonReader.readObject();
            jsonReader.close();

            return body;
        } catch (Exception e) {
            log.error(e);
        }
        return null;
    }

    /**
     * This function will be called on every http request if doSSLVerify is set to false
     */
    private HttpsURLConnection turnOffSSLVerification(HttpsURLConnection con) {
        final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{};
                    }
                }
        };
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }

        if (sslContext == null) {
            return con;
        }

        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        con.setSSLSocketFactory(sslSocketFactory);
        con.setHostnameVerifier((hostname, session) -> true);

        return con;
    }

    @Override
    public boolean requiresUser() {
        log.debug("requiresUser");
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        log.debug("configuredFor");
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        log.debug("setRequiredActions");
    }

    @Override
    public void close() {
        log.debug("close");
    }
}
