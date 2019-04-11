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

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.StringReader;

import java.net.URL;
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

public class privacyIDEAAuthenticator implements Authenticator {

    public static final String CREDENTIAL_TYPE = "pi_otp";


    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challenge = context.form().createForm("privacyIDEA.ftl");
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        boolean validated = validateAnswer(context);

        if (!validated) {
            Response challenge =  context.form()
                    .setError("Authentication failed.")
                    .createForm("privacyIDEA.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }
        context.success();
    }


    protected boolean validateAnswer(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String otp = formData.getFirst("pi_otp");

        UserModel user = context.getUser();
        String username = user.getUsername();


        try {

            AuthenticatorConfigModel acm = context.getAuthenticatorConfig();
            Map<String,String> configMap = acm.getConfig();
            String piserver = configMap.get("piserver");
            String pirealm = configMap.get("pirealm");
            String piverifyssl = configMap.get("piverifyssl");

            if (pirealm == null) {
                pirealm = "";
            }

            URL piserverurl = new URL(piserver + "/validate/check");
            String piServerProtocol = piserverurl.getProtocol();

            HttpURLConnection con;

            if (piServerProtocol.equals("https")) {
                con = (HttpsURLConnection) (piserverurl.openConnection());
            } else {
                con = (HttpURLConnection) (piserverurl.openConnection());
            }

            if (piverifyssl.equals("false") && con instanceof HttpsURLConnection) {
                con = turnOffSSLVerification((HttpsURLConnection) con);
            }

            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.connect();

            byte[] outputBytes = ("user=" + username + "&pass=" + otp + "&realm=" + pirealm).getBytes("UTF-8");
            OutputStream os = con.getOutputStream();
            os.write(outputBytes);
            os.close();

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

            JsonObject result = body.getJsonObject("result");
            boolean value = result.getBoolean("value");

            return value;
        } catch (Exception e) {
            System.out.println(e);
        }

        return false;
    }


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
