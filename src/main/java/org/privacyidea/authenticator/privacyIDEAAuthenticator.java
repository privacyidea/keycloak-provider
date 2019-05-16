/**
 * Copyright 2019 NetKnights GmbH - micha.preusser@neknights.it
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

import org.jboss.resteasy.spi.HttpResponse;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.GroupModel;
import org.keycloak.forms.login.LoginFormsProvider;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.StringReader;

import java.net.HttpURLConnection;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;

import javax.json.*;
import java.util.Map;
import java.util.Set;

public class privacyIDEAAuthenticator implements Authenticator {

    public static final String CREDENTIAL_TYPE = "pi_otp";

    /**
     * Server URL
     */
    private String piserver;

    /**
     * The privacyIDEA realm, where the users are located in
     */
    private String pirealm;

    /**
     * Verify ssl to privacyIDEA
     */
    private boolean piverifyssl;

    /**
     * Check if trigger challenge is enabled
     */
    private boolean pidotriggerchallenge;

    /**
     * Username for service account
     */
    private String piserviceaccount;

    /**
     * Password for service account
     */
    private String piservicepass;

    /**
     * Groups in Keycloak, which are excluded from 2fa (comma separated)
     */
    private String piexcludegroups;

    /**
     * Enable or disable token enrollment if user does not have a token yet.
     */
    private boolean pienrolltoken;

    /**
     * If token enrollment is enabled, you can select the type for new tokens.
     */
    private String pienrolltokentype;

    /**
     * The interval for refreshing page to check if the push token was confirmed
     */
    private int pipushtokeninterval[];

    /**
     * The Authozitaion token for the service account, which will be set after a successful trigger challenge
     */
    private String authToken;


    /**
     * This function will be called in the moment,
     * when the authentication flow triggeres the privacyIDEA execution.
     *
     * @param context
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {

        /**
         * Username of the current user
         */
        String username;

        /**
         * QR code to for the new enrolled token
         */
        String tokenEnrollmentQR = "";

        /**
         * Token type for the token which will be used.
         */
        String tokenType = "otp";

        /**
         * Indicated if push token is available
         */
        boolean pushToken = false;

        /**
         * Indicates if otp token is available
         */
        boolean otpToken = false;

        /**
         * Message for push token
         */
        String pushMessage = null;

        /**
         * Message for every token with input field
         */
        String otpMessage = null;

        UserModel user = context.getUser();
        username = user.getUsername();

        Set<GroupModel> groupModelSet = user.getGroups();
        GroupModel[] groupModels = groupModelSet.toArray(new GroupModel[0]);

        /**
         * Get configuration
         */

        AuthenticatorConfigModel acm = context.getAuthenticatorConfig();
        Map<String,String> configMap = acm.getConfig();
        this.piserver = configMap.get("piserver");
        this.pirealm = configMap.get("pirealm") == null ? "" : configMap.get("pirealm");
        this.piverifyssl = configMap.get("piverifyssl") == null ? false : configMap.get("piverifyssl").equals("true");
        this.pidotriggerchallenge = configMap.get("pidotriggerchallenge") == null ? false : configMap.get("pidotriggerchallenge").equals("true");
        this.piserviceaccount = configMap.get("piserviceaccount") == null ? "" : configMap.get("piserviceaccount");
        this.piservicepass = configMap.get("piservicepass") == null ? "" : configMap.get("piservicepass");
        this.piexcludegroups = configMap.get("piexcludegroups") == null ? "" : configMap.get("piexcludegroups");
        this.pienrolltoken = configMap.get("pienrolltoken") == null ? false : configMap.get("pienrolltoken").equals("true");
        this.pienrolltokentype = configMap.get("pienrolltokentype") == null ? "" : configMap.get("pienrolltokentype");

        String pipushtokeninterval[];
        if (configMap.get("pipushtokeninterval") == null) {
            pipushtokeninterval = new String[1];
        } else {
            pipushtokeninterval = configMap.get("pipushtokeninterval").split(",");
        }
        this.pipushtokeninterval = new int[pipushtokeninterval.length];
        try {
            for (int i = 0; i < pipushtokeninterval.length; i++) {
                this.pipushtokeninterval[i] = Integer.parseInt(pipushtokeninterval[i]);
            }
        } catch (Exception e) {
            this.pipushtokeninterval = new int[]{5,1,1,1,2,3};
        }

        String piexcludegroups[] = this.piexcludegroups.split(",");

        /**
         * Check if privacyIDEA is enabled for current user
         */

        for (GroupModel groupModel : groupModels) {
            for (String excludedGroup : piexcludegroups) {
                if (groupModel.getName().equals(excludedGroup)) {
                    context.success();
                    return;
                }
            }
        }

        int tokenCounter = 0;

        /**
         * Trigger challenge for current user
         */

        if (pidotriggerchallenge) {

            String params = "username=" + this.piserviceaccount + "&password=" + this.piservicepass;
            JsonObject body = httpConnection("/auth", params, null, "POST");
            try {
                JsonObject result = body.getJsonObject("result");
                JsonObject value = result.getJsonObject("value");
                this.authToken = value.getString("token");
            } catch (Exception e) {

            }

            params = "user=" + username;
            body = httpConnection("/validate/triggerchallenge", params, this.authToken, "POST");

            try {
                JsonObject detail = body.getJsonObject("detail");
                JsonObject result = body.getJsonObject("result");
                tokenCounter = result.getInt("value");
                context.getAuthenticationSession().setAuthNote("pi.transaction_id", detail.getString("transaction_id"));
                JsonArray multi_challenge = detail.getJsonArray("multi_challenge");
                for (int i = 0; i < multi_challenge.size(); i++) {
                    JsonObject challenge = multi_challenge.getJsonObject(i);
                    if (challenge.getString("type").equals("push")) {
                        pushToken = true;
                        if (pushMessage == null) {
                            pushMessage = challenge.getString("message");
                        } else {
                            pushMessage = pushMessage + ", " + challenge.getString("message");
                        }
                    } else {
                        otpToken = true;
                        if (otpMessage == null) {
                            otpMessage = challenge.getString("message");
                        } else {
                            otpMessage = otpMessage + ", " + challenge.getString("message");
                        }
                    }
                }
                if (pushToken) {
                    tokenType = "push";
                }
            } catch (Exception e) {

            }

            /**
             * Enroll token if enabled and user does not have one
             */

            if (this.pienrolltoken && tokenCounter == 0) {

                params = "user=" + username + "&type=" + this.pienrolltokentype + "&genkey=1";
                body = httpConnection("/token/init", params, this.authToken, "POST");

                try {
                    JsonObject detail = body.getJsonObject("detail");
                    JsonObject googleurl = detail.getJsonObject("googleurl");
                    tokenEnrollmentQR = googleurl.getString("img");
                } catch (Exception e) {

                }
            }
        }

        context.getAuthenticationSession().setAuthNote("authCounter", "0");

        /**
         * Create login form
         */

        Response challenge;

        challenge = context.form()
                .setAttribute("pushTokenInterval", this.pipushtokeninterval[0])
                .setAttribute("tokenEnrollmentQR", tokenEnrollmentQR)
                .setAttribute("tokenType", tokenType)
                .setAttribute("pushToken", pushToken)
                .setAttribute("otpToken", otpToken)
                .setAttribute("pushMessage", pushMessage == null ? "" : pushMessage)
                .setAttribute("otpMessage", otpMessage == null ? "" : otpMessage)
                .createForm("privacyIDEA.ftl");

        context.challenge(challenge);
    }

    /**
     * This function will be called if the user submitted the form
     *
     * @param context
     */

    @Override
    public void action(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        /**
         * Get data from form
         */

        String tokenEnrollmentQR = formData.getFirst("tokenEnrollmentQR");
        String tokenType = formData.getFirst("tokenType");
        boolean pushToken = formData.getFirst("pushToken").equals("true") ? true : false;
        boolean otpToken = formData.getFirst("otpToken").equals("true") ? true : false;
        String transaction_id = (String)context.getAuthenticationSession().getAuthNote("pi.transaction_id");
        String pushMessage = formData.getFirst("pushMessage");
        String otpMessage = formData.getFirst("otpMessage");
        String tokenTypeChanged = formData.getFirst("tokenTypeChanged");

        boolean validated = validateAnswer(context);

        if (!validated) {

            int authCounter = Integer.parseInt(context.getAuthenticationSession().getAuthNote("authCounter")) + 1;
            authCounter = (authCounter >= this.pipushtokeninterval.length ? this.pipushtokeninterval.length - 1 : authCounter);
            context.getAuthenticationSession().setAuthNote("authCounter", Integer.toString(authCounter));


            LoginFormsProvider form = context.form()
                    .setAttribute("pushTokenInterval", this.pipushtokeninterval[authCounter])
                    .setAttribute("tokenEnrollmentQR", tokenEnrollmentQR)
                    .setAttribute("tokenType", tokenType)
                    .setAttribute("pushToken", pushToken)
                    .setAttribute("otpToken", otpToken)
                    .setAttribute("pushMessage", pushMessage == null ? "" : pushMessage)
                    .setAttribute("otpMessage", otpMessage == null ? "" : otpMessage);

            if (tokenType.equals("push") || tokenTypeChanged.equals("true")) {

            } else {
                form.setError("Authentication failed.");
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
     * @param context
     * @return true if authentication was successful, else false
     */
    protected boolean validateAnswer(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        UserModel user = context.getUser();
        String username = user.getUsername();

        /**
         * Get data from form
         */

        String tokenEnrollmentQR = formData.getFirst("tokenEnrollmentQR");
        String tokenType = formData.getFirst("tokenType");
        boolean pushToken = formData.getFirst("pushToken").equals("true") ? true : false;
        boolean otpToken = formData.getFirst("otpToken").equals("true") ? true : false;
        String transaction_id = (String)context.getAuthenticationSession().getAuthNote("pi.transaction_id");
        String pushMessage = formData.getFirst("pushMessage");
        String otpMessage = formData.getFirst("otpMessage");

        if (formData.getFirst("tokenTypeChanged").equals("true")) {
            return false;
        }

        if (tokenType.equals("push")) {
            JsonObject body = httpConnection("/token/challenges/", null, this.authToken, "GET");
            try {
                JsonObject result = body.getJsonObject("result");
                JsonObject value = result.getJsonObject("value");
                JsonArray challenges = value.getJsonArray("challenges");
                for (int i = 0; i < challenges.size(); i++) {
                    JsonObject challenge = challenges.getJsonObject(i);
                    String JsonTransaction_id = challenge.getString("transaction_id");
                    if (transaction_id.equals(JsonTransaction_id)) {
                        boolean otp_valid = challenge.getBoolean("otp_valid");
                        if (otp_valid) {
                            return true;
                        }
                    }
                }
            } catch (Exception e) {

            }
            return false;
        }

        String otp = formData.getFirst("pi_otp");
        String params = "user=" + username + "&pass=" + otp + "&realm=" + this.pirealm;

        JsonObject body = httpConnection("/validate/check", params, null, "POST");
        try {
            JsonObject result = body.getJsonObject("result");
            boolean value = result.getBoolean("value");
            return value;
        } catch (Exception e) {

        }
        return false;

    }


    /**
     * This function will be called for every http request.
     *
     * @param path
     * Api endpoint for request
     *
     * @param params
     * All necessary parameters for request
     *
     * @param authToken
     * The auth token for the service account (null, if not necessary)
     *
     * @param method
     * "POST" or "GET"
     *
     * @return JsonObject body which contains the whole response
     */
    protected JsonObject httpConnection(String path, String params, String authToken, String method) {
        try {
            URL piserverurl = new URL(this.piserver + path);

            if (method.equals("GET") && params != null) {
                piserverurl = new URL(this.piserver + path + "?" + params);
            }

            String piServerProtocol = piserverurl.getProtocol();

            HttpURLConnection con;

            if (piServerProtocol.equals("https")) {
                con = (HttpsURLConnection) (piserverurl.openConnection());
            } else {
                con = (HttpURLConnection) (piserverurl.openConnection());
            }

            if (!this.piverifyssl && con instanceof HttpsURLConnection) {
                con = turnOffSSLVerification((HttpsURLConnection) con);
            }

            con.setDoOutput(true);
            con.setRequestMethod(method);
            if (authToken != null) {
                con.setRequestProperty("Authorization", authToken);
            }
            con.connect();

            if (method.equals("POST")) {
                byte[] outputBytes = (params).getBytes("UTF-8");
                OutputStream os = con.getOutputStream();
                os.write(outputBytes);
                os.close();
            }

            String bodyString;
            BufferedInputStream bufferedInputStream = new BufferedInputStream(con.getInputStream());
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            int bodyInt = bufferedInputStream.read();
            while (bodyInt != -1) {
                byteArrayOutputStream.write((byte) bodyInt);
                bodyInt = bufferedInputStream.read();
            }
            bodyString = byteArrayOutputStream.toString();

            JsonReader jsonReader = Json.createReader(new StringReader(bodyString));
            JsonObject body = jsonReader.readObject();
            jsonReader.close();


            return body;

        } catch (Exception e) {

        }
        return null;
    }

    /**
     * This function will be called on every http request if piverifyssl is set to false
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
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        con.setSSLSocketFactory(sslSocketFactory);
        con.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
        return con;
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
