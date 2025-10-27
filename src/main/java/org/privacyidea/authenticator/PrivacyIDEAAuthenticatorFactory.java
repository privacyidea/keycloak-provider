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

import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class PrivacyIDEAAuthenticatorFactory implements org.keycloak.authentication.AuthenticatorFactory, org.keycloak.authentication.ConfigurableAuthenticatorFactory
{
    private static final PrivacyIDEAAuthenticator SINGLETON = new PrivacyIDEAAuthenticator();
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public String getId()
    {
        return Const.PROVIDER_ID;
    }

    @Override
    public org.keycloak.authentication.Authenticator create(KeycloakSession session)
    {
        return SINGLETON;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices()
    {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed()
    {
        return false;
    }

    @Override
    public boolean isConfigurable()
    {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties()
    {
        return configProperties;
    }

    static
    {
        ProviderConfigProperty serverURL = new ProviderConfigProperty();
        serverURL.setType(ProviderConfigProperty.STRING_TYPE);
        serverURL.setName(Const.CONFIG_SERVER);
        serverURL.setLabel("PrivacyIDEA URL");
        serverURL.setRequired(true);
        serverURL.setHelpText("The URL of the privacyIDEA server. Example: https://privacyidea.company.com");
        configProperties.add(serverURL);

        ProviderConfigProperty realm = new ProviderConfigProperty();
        realm.setType(ProviderConfigProperty.STRING_TYPE);
        realm.setName(Const.CONFIG_REALM);
        realm.setLabel("Realm");
        realm.setHelpText("Select the realm where your users are stored. Leave empty to use the default realm " +
                          "which is configured in the privacyIDEA server.");
        configProperties.add(realm);

        ProviderConfigProperty verifySSL = new ProviderConfigProperty();
        verifySSL.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        verifySSL.setName(Const.CONFIG_VERIFY_SSL);
        verifySSL.setLabel("Verify SSL");
        verifySSL.setHelpText("Do not set this to false in a productive environment. " +
                              "Disables the verification of the privacyIDEA server's certificate and hostname.");
        configProperties.add(verifySSL);

        ProviderConfigProperty triggerChallenge = new ProviderConfigProperty();
        triggerChallenge.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        triggerChallenge.setName(Const.CONFIG_TRIGGER_CHALLENGE);
        triggerChallenge.setLabel("Enable Trigger Challenge");
        triggerChallenge.setHelpText("Choose if you want to trigger challenge-response token " +
                                     "using the provided service account before the second step of authentication. " +
                                     "This setting is mutually exclusive with sending any password " +
                                     "and will take precedence over both.");
        configProperties.add(triggerChallenge);

        ProviderConfigProperty serviceAccountName = new ProviderConfigProperty();
        serviceAccountName.setType(ProviderConfigProperty.STRING_TYPE);
        serviceAccountName.setName(Const.CONFIG_SERVICE_ACCOUNT);
        serviceAccountName.setLabel("Service Account");
        serviceAccountName.setHelpText("Username of the service account. Needed for trigger challenge and token enrollment.");
        configProperties.add(serviceAccountName);

        ProviderConfigProperty serviceAccountPass = new ProviderConfigProperty();
        serviceAccountPass.setType(ProviderConfigProperty.PASSWORD);
        serviceAccountPass.setName(Const.CONFIG_SERVICE_PASS);
        serviceAccountPass.setLabel("Service Account Password");
        serviceAccountPass.setHelpText("Password of the service account. Needed for trigger challenge and token enrollment.");
        configProperties.add(serviceAccountPass);

        ProviderConfigProperty serviceAccountRealm = new ProviderConfigProperty();
        serviceAccountRealm.setType(ProviderConfigProperty.STRING_TYPE);
        serviceAccountRealm.setName(Const.CONFIG_SERVICE_REALM);
        serviceAccountRealm.setLabel("Service Account Realm");
        serviceAccountRealm.setHelpText("Realm of the service account, if it is in a separate realm from the other accounts. " +
                                        "Leave empty to use the general realm specified or the default realm " +
                                        "if no realm is configured at all.");
        configProperties.add(serviceAccountRealm);

        ProviderConfigProperty sendPassword = new ProviderConfigProperty();
        sendPassword.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        sendPassword.setName(Const.CONFIG_SEND_PASSWORD);
        sendPassword.setLabel("Send Password");
        sendPassword.setHelpText("Choose if you want to send the password from the first login step to privacyIDEA. " +
                                 "This can be used to trigger challenge-response token. " +
                                 "This setting is mutually exclusive with trigger challenge and sending a static pass.");
        configProperties.add(sendPassword);

        ProviderConfigProperty sendStaticPass = new ProviderConfigProperty();
        sendStaticPass.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        sendStaticPass.setName(Const.CONFIG_SEND_STATIC_PASS);
        sendStaticPass.setLabel("Send Static Password");
        sendStaticPass.setHelpText("Enable to send the specified static password to privacyIDEA. " +
                                   "Mutually exclusive with sending the password and trigger challenge.");
        configProperties.add(sendStaticPass);

        ProviderConfigProperty staticPass = new ProviderConfigProperty();
        staticPass.setType(ProviderConfigProperty.PASSWORD);
        staticPass.setName(Const.CONFIG_STATIC_PASS);
        staticPass.setLabel("Static Password");
        staticPass.setHelpText("Set the static password which should be sent to privacyIDEA if \"send static password\" is enabled. " +
                               "Can be empty to send an empty password.");
        configProperties.add(staticPass);

        ProviderConfigProperty disablePasswordCheck = new ProviderConfigProperty();
        disablePasswordCheck.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        disablePasswordCheck.setDefaultValue(false);
        disablePasswordCheck.setName(Const.CONFIG_DISABLE_PASSWORD_CHECK);
        disablePasswordCheck.setLabel("Disable Password Check");
        disablePasswordCheck.setHelpText("Whether the user is required to enter the password. Can be disabled to add the keycloak password " +
                                         "step after the privacyIDEA step or require no password at all.");
        configProperties.add(disablePasswordCheck);

        ProviderConfigProperty disablePasskeyLogin = new ProviderConfigProperty();
        disablePasskeyLogin.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        disablePasskeyLogin.setDefaultValue(false);
        disablePasskeyLogin.setName(Const.CONFIG_DISABLE_PASSKEY_LOGIN);
        disablePasskeyLogin.setLabel("Disable Passkey Login");
        disablePasskeyLogin.setHelpText("Disable the passkey login button, removing the option to log in with passkeys. " +
                                        "NOTE: If this is enabled, the 'Passkey Only' option will be ignored.");
        configProperties.add(disablePasskeyLogin);

        ProviderConfigProperty passkeyOnly = new ProviderConfigProperty();
        passkeyOnly.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        passkeyOnly.setName(Const.CONFIG_PASSKEY_ONLY);
        passkeyOnly.setLabel("Passkey Only");
        passkeyOnly.setDefaultValue(false);
        passkeyOnly.setHelpText("Enable this to run the privacyIDEA Provider in the Passkey Only mode. " +
                                "When enabled, authentication will only be possible using passkeys. " +
                                "PUSH, One-Time Passwords, and other tokens will not be accessible for users." +
                                "NOTE: This requires that users have passkeys enrolled in privacyIDEA." +
                                "NOTE: Remember to not enable the 'Disable Passkey Login' option. Otherwise, this will be ignored.");
        configProperties.add(passkeyOnly);

        ProviderConfigProperty includedGroups = new ProviderConfigProperty();
        includedGroups.setType(ProviderConfigProperty.STRING_TYPE);
        includedGroups.setName(Const.CONFIG_INCLUDED_GROUPS);
        includedGroups.setLabel("Included groups");
        includedGroups.setHelpText("Set groups for which the privacyIDEA workflow will be activated. " +
                                   "The names should be separated with ',' (E.g. group1,group2)" +
                                   "NOTE: By the usernameless authentication, the group membership check will be ignored!");
        configProperties.add(includedGroups);

        ProviderConfigProperty excludedGroups = new ProviderConfigProperty();
        excludedGroups.setType(ProviderConfigProperty.STRING_TYPE);
        excludedGroups.setName(Const.CONFIG_EXCLUDED_GROUPS);
        excludedGroups.setLabel("Excluded groups");
        excludedGroups.setHelpText("Set groups for which the privacyIDEA workflow will be skipped. " +
                                   "The names should be separated with ',' (E.g. group1,group2). " +
                                   "If chosen group is already set in 'Included groups', " + "excluding for this group will be ignored. " +
                                   "NOTE: By the usernameless authentication, the group membership check will be ignored!");
        configProperties.add(excludedGroups);

        ProviderConfigProperty autoSubmitLength = new ProviderConfigProperty();
        autoSubmitLength.setType(ProviderConfigProperty.STRING_TYPE);
        autoSubmitLength.setName(Const.CONFIG_OTP_LENGTH);
        autoSubmitLength.setLabel("Auto-Submit OTP Length");
        autoSubmitLength.setHelpText("Automatically submit the login form after X digits were entered. " +
                                     "Leave empty to disable. NOTE: Only digits can be entered!");
        configProperties.add(autoSubmitLength);

        ProviderConfigProperty forwardClientIP = new ProviderConfigProperty();
        forwardClientIP.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        forwardClientIP.setName(Const.CONFIG_FORWARD_CLIENT_IP);
        forwardClientIP.setLabel("Forward Client IP");
        forwardClientIP.setHelpText("Enable this to forward the client IP to privacyIDEA. This can be used in privacyIDEA server if configured.");
        configProperties.add(forwardClientIP);

        ProviderConfigProperty httpTimeoutMs = new ProviderConfigProperty();
        httpTimeoutMs.setType(ProviderConfigProperty.STRING_TYPE);
        httpTimeoutMs.setName(Const.CONFIG_HTTP_TIMEOUT_MS);
        httpTimeoutMs.setLabel("HTTP Timeout (ms)");
        httpTimeoutMs.setHelpText("Set the HTTP timeout to a custom value. Timeunit is milliseconds. " +
                                  "Leave empty to use the default value of 10 seconds.");
        configProperties.add(httpTimeoutMs);

        ProviderConfigProperty forwardHeaders = new ProviderConfigProperty();
        forwardHeaders.setType(ProviderConfigProperty.STRING_TYPE);
        forwardHeaders.setName(Const.CONFIG_FORWARDED_HEADERS);
        forwardHeaders.setLabel("Headers to Forward");
        forwardHeaders.setHelpText("Set the headers which should be forwarded to privacyIDEA. " +
                                   "If the header does not exist or has no value, it will be ignored. " +
                                   "The headers should be separated with ','.");
        configProperties.add(forwardHeaders);

        ProviderConfigProperty customHeaders = new ProviderConfigProperty();
        customHeaders.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        customHeaders.setName(Const.CONFIG_CUSTOM_HEADERS);
        customHeaders.setLabel("Custom Headers");
        customHeaders.setHelpText("Set custom headers to send with each request. Each entry needs to have the format key=value. " +
                                  "Entries that do not have this format will be ignored. Do not use well known headers like 'Authorization' " +
                                  "and do not use '##'.");
        configProperties.add(customHeaders);

        ProviderConfigProperty pollInBrowser = new ProviderConfigProperty();
        pollInBrowser.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        pollInBrowser.setName(Const.CONFIG_POLL_IN_BROWSER);
        pollInBrowser.setLabel("Poll in Browser");
        pollInBrowser.setDefaultValue(false);
        pollInBrowser.setHelpText("Enable this to do the polling for accepted push requests in the user's browser. " +
                                  "When enabled, the login page does not refresh when checking for successful push authentication. " +
                                  "NOTE: privacyIDEA has to be reachable from the user's browser and a valid SSL certificate has to be in place.");
        configProperties.add(pollInBrowser);

        ProviderConfigProperty pollInBrowserURL = new ProviderConfigProperty();
        pollInBrowserURL.setType(ProviderConfigProperty.STRING_TYPE);
        pollInBrowserURL.setName(Const.CONFIG_POLL_IN_BROWSER_URL);
        pollInBrowserURL.setLabel("URL for Poll in Browser");
        pollInBrowserURL.setHelpText("Optional. If poll in browser should use a deviating URL, set it here. " +
                                     "Otherwise, the general URL will be used.");
        configProperties.add(pollInBrowserURL);

        ProviderConfigProperty debugLog = new ProviderConfigProperty();
        debugLog.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        debugLog.setName(Const.CONFIG_ENABLE_LOG);
        debugLog.setLabel("Enable Logging");
        debugLog.setHelpText("If enabled, log messages will be written to the keycloak server logfile.");
        debugLog.setDefaultValue(false);
        configProperties.add(debugLog);
    }

    @Override
    public String getHelpText()
    {
        return "Authenticate the second factor against privacyIDEA.";
    }

    @Override
    public String getDisplayType()
    {
        return "privacyIDEA";
    }

    @Override
    public String getReferenceCategory()
    {
        return "privacyIDEA";
    }

    @Override
    public void init(Config.Scope config)
    {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory)
    {
    }

    @Override
    public void close()
    {
    }
}