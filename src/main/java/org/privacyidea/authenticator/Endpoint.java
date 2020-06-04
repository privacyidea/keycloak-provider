package org.privacyidea.authenticator;

import org.jboss.logging.Logger;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.privacyidea.authenticator.Const.*;

class Endpoint {

    private Logger _log = Logger.getLogger(getClass().getName());
    private Configuration _config;
    private List<String> excludedEndpointPrints = Collections.emptyList(); //Arrays.asList(ENDPOINT_AUTH);

    Endpoint(Configuration config) {
        this._config = config;
    }

    /**
     * Make a http(s) call to the specified path, the URL is taken from the config.
     * If SSL Verification is turned off in the config, the endpoints certificate will not be verified.
     *
     * @param path              Path to the API endpoint
     * @param params            All necessary parameters for request
     * @param authTokenRequired whether the authorization header should be set
     * @param method            "POST" or "GET"
     * @return JsonObject body which contains the whole response
     */
    JsonObject sendRequest(String path, Map<String, String> params, boolean authTokenRequired, String method) {
        //_log.info("Sending to endpoint=" + path + " with params=" + params.toString() + " and method=" + method);
        StringBuilder paramsSB = new StringBuilder();
        params.forEach((key, value) -> {
            try {
                if (key != null) {
                    paramsSB.append(key).append("=");
                }
                if (value != null) {
                    paramsSB.append(URLEncoder.encode(value, StandardCharsets.UTF_8.toString()));
                }
                paramsSB.append("&");
            } catch (Exception e) {
                _log.error(e);
            }
        });

        if (paramsSB.length() > 0) {
            paramsSB.deleteCharAt(paramsSB.length() - 1);
        }
        //_log.info("Params: " + paramsSB);

        try {
            URL serverURL;
            if (method.equals(GET)) {
                serverURL = new URL(_config.getServerURL() + path + "?" + paramsSB.toString());
            } else {
                serverURL = new URL(_config.getServerURL() + path);
            }
            _log.info("Connecting to: " + serverURL.toExternalForm() + " with " + method);
            _log.info("Params: " + paramsSB.toString());
            HttpURLConnection con;
            if (serverURL.getProtocol().equals("https")) {
                con = (HttpsURLConnection) (serverURL.openConnection());
            } else {
                con = (HttpURLConnection) (serverURL.openConnection());
            }

            if (!_config.doSSLVerify() && con instanceof HttpsURLConnection) {
                con = turnOffSSLVerification((HttpsURLConnection) con);
            }

            con.setRequestMethod(method);

            if (method.equals("POST")) {
                con.setDoOutput(true);
            }

            if (authTokenRequired) {
                String authToken = getAuthorizationToken();
                if (authToken == null) {

                }
                _log.info("Setting auth token: " + authToken);
                con.setRequestProperty("Authorization", authToken);
            }

            con.connect();

            if (method.equals(POST)) {
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

            if (!excludedEndpointPrints.contains(path)) {
                _log.info(path + " RESPONSE: " + Utilities.prettyPrintJson(response));
            }

            JsonReader jsonReader = Json.createReader(new StringReader(response));
            JsonObject body = jsonReader.readObject();
            jsonReader.close();

            return body;
        } catch (Exception e) {
            e.printStackTrace();
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

    private String getAuthorizationToken() {
        if (_config.getServiceAccountName() == null || _config.getServiceAccountName().isEmpty() || _config.getServiceAccountPass() == null
                || _config.getServiceAccountPass().isEmpty()) {
            _log.error("Cannot retrieve authorization token without service account!");
            return null;
        }

        String authToken = null;
        _log.info("Getting auth token from PI");
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_KEY_USERNAME, _config.getServiceAccountName());
        params.put(PARAM_KEY_PASSWORD, _config.getServiceAccountPass());
        JsonObject body = sendRequest(ENDPOINT_AUTH, params, false, POST);
        JsonObject result = body.getJsonObject(JSON_KEY_RESULT);
        if (result != null) {
            JsonObject value = result.getJsonObject(JSON_KEY_VALUE);
            if (value != null) {
                authToken = value.getString(JSON_KEY_TOKEN, null);
            }
        }

        //_log.info("Auth Token: " + authToken);
        if (authToken == null) {
            _log.error("Failed to get authorization token.");
            //_log.error("Unable to read response from privacyIDEA.");
        }
        return authToken;
    }
}
