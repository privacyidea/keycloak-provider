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
import java.util.Arrays;
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

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED};

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
        ProviderConfigProperty piServerUrl = new ProviderConfigProperty();
        piServerUrl.setType(ProviderConfigProperty.STRING_TYPE);
        piServerUrl.setName(Const.CONFIG_SERVER);
        piServerUrl.setLabel("privacyIDEA URL");
        piServerUrl.setHelpText("The URL of the privacyIDEA server (complete with scheme, host and port like \"https://<piserver>:port\")");
        configProperties.add(piServerUrl);

        ProviderConfigProperty piRealm = new ProviderConfigProperty();
        piRealm.setType(ProviderConfigProperty.STRING_TYPE);
        piRealm.setName(Const.CONFIG_REALM);
        piRealm.setLabel("Realm");
        piRealm.setHelpText(
                "Select the realm where your users are stored. Leave empty to use the default realm which is configured in the privacyIDEA server.");
        configProperties.add(piRealm);

        ProviderConfigProperty piVerifySSL = new ProviderConfigProperty();
        piVerifySSL.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piVerifySSL.setName(Const.CONFIG_VERIFY_SSL);
        piVerifySSL.setLabel("Verify SSL");
        piVerifySSL.setHelpText(
                "Do not set this to false in a productive environment. Disables the verification of the privacyIDEA server's certificate and hostname.");
        configProperties.add(piVerifySSL);

        ProviderConfigProperty piDoTriggerChallenge = new ProviderConfigProperty();
        piDoTriggerChallenge.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piDoTriggerChallenge.setName(Const.CONFIG_TRIGGER_CHALLENGE);
        piDoTriggerChallenge.setLabel("Enable trigger challenge");
        piDoTriggerChallenge.setHelpText(
                "Choose if you want to trigger challenge-response token using the provided service account before the second step of authentication. " +
                        "This setting is mutually exclusive with sending any password and will take precedence over both.");
        configProperties.add(piDoTriggerChallenge);

        ProviderConfigProperty piServiceAccount = new ProviderConfigProperty();
        piServiceAccount.setType(ProviderConfigProperty.STRING_TYPE);
        piServiceAccount.setName(Const.CONFIG_SERVICE_ACCOUNT);
        piServiceAccount.setLabel("Service account");
        piServiceAccount.setHelpText("Username of the service account. Needed for trigger challenge and token enrollment.");
        configProperties.add(piServiceAccount);

        ProviderConfigProperty piServicePass = new ProviderConfigProperty();
        piServicePass.setType(ProviderConfigProperty.PASSWORD);
        piServicePass.setName(Const.CONFIG_SERVICE_PASS);
        piServicePass.setLabel("Service account password");
        piServicePass.setHelpText("Password of the service account. Needed for trigger challenge and token enrollment.");
        configProperties.add(piServicePass);

        ProviderConfigProperty piServiceRealm = new ProviderConfigProperty();
        piServiceRealm.setType(ProviderConfigProperty.STRING_TYPE);
        piServiceRealm.setName(Const.CONFIG_SERVICE_REALM);
        piServiceRealm.setLabel("Service account realm");
        piServiceRealm.setHelpText("Realm of the service account, if it is in a separate realm from the other accounts. " +
                "Leave empty to use the general realm specified or the default realm if no realm is configured at all.");
        configProperties.add(piServiceRealm);

        ProviderConfigProperty piDoSendPassword = new ProviderConfigProperty();
        piDoSendPassword.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piDoSendPassword.setName(Const.CONFIG_SEND_PASSWORD);
        piDoSendPassword.setLabel("Send password");
        piDoSendPassword.setHelpText(
                "Choose if you want to send the password from the first login step to privacyIDEA. This can be used to trigger challenge-response token. " +
                        "This setting is mutually exclusive with trigger challenge and sending a static pass.");
        configProperties.add(piDoSendPassword);

        ProviderConfigProperty piSendStaticPass = new ProviderConfigProperty();
        piSendStaticPass.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piSendStaticPass.setName(Const.CONFIG_SEND_STATIC_PASS);
        piSendStaticPass.setLabel("Send static password");
        piSendStaticPass.setHelpText("Enable to send the specified static password to privacyIDEA. Mutually exclusive with sending the password and trigger challenge.");
        configProperties.add(piSendStaticPass);

        ProviderConfigProperty piStaticPass = new ProviderConfigProperty();
        piStaticPass.setType(ProviderConfigProperty.PASSWORD);
        piStaticPass.setName(Const.CONFIG_STATIC_PASS);
        piStaticPass.setLabel("Static pass");
        piStaticPass.setHelpText("Set the static password which should be sent to privacyIDEA if \"send static password\" is enabled. " +
                "Can be empty to send an empty password.");
        configProperties.add(piStaticPass);

        ProviderConfigProperty piIncludeGroups = new ProviderConfigProperty();
        piIncludeGroups.setType(ProviderConfigProperty.STRING_TYPE);
        piIncludeGroups.setName(Const.CONFIG_INCLUDED_GROUPS);
        piIncludeGroups.setLabel("Included groups");
        piIncludeGroups.setHelpText(
                "Set groups for which the privacyIDEA workflow will be activated. The names should be separated with ',' (E.g. group1,group2)");
        configProperties.add(piIncludeGroups);

        ProviderConfigProperty piExcludeGroups = new ProviderConfigProperty();
        piExcludeGroups.setType(ProviderConfigProperty.STRING_TYPE);
        piExcludeGroups.setName(Const.CONFIG_EXCLUDED_GROUPS);
        piExcludeGroups.setLabel("Excluded groups");
        piExcludeGroups.setHelpText(
                "Set groups for which the privacyIDEA workflow will be skipped. The names should be separated with ',' (E.g. group1,group2). " +
                        "If chosen group is already set in 'Included groups', excluding for this group will be ignored.");
        configProperties.add(piExcludeGroups);

        ProviderConfigProperty piDefaultOTPText = new ProviderConfigProperty();
        piDefaultOTPText.setType(ProviderConfigProperty.STRING_TYPE);
        piDefaultOTPText.setName(Const.CONFIG_DEFAULT_MESSAGE);
        piDefaultOTPText.setLabel("Default OTP Text");
        piDefaultOTPText.setHelpText(
                "Set the default OTP text that will be shown if no challenge or error messages are present.");
        configProperties.add(piDefaultOTPText);

        ProviderConfigProperty piOtpLength = new ProviderConfigProperty();
        piOtpLength.setType(ProviderConfigProperty.STRING_TYPE);
        piOtpLength.setName(Const.CONFIG_OTP_LENGTH);
        piOtpLength.setLabel("Auto-Submit OTP Length");
        piOtpLength.setHelpText("Automatically submit the login form after X digits were entered. Leave empty to disable. NOTE: Only digits can be entered!");
        configProperties.add(piOtpLength);

        ProviderConfigProperty piForwardedHeaders = new ProviderConfigProperty();
        piForwardedHeaders.setType(ProviderConfigProperty.STRING_TYPE);
        piForwardedHeaders.setName(Const.CONFIG_FORWARDED_HEADERS);
        piForwardedHeaders.setLabel("Headers to forward");
        piForwardedHeaders.setHelpText(
                "Set the headers which should be forwarded to privacyIDEA. If the header does not exist or has no value, it will be ignored. " +
                        "The headers should be separated with ','.");
        configProperties.add(piForwardedHeaders);

        ProviderConfigProperty piPollInBrowser = new ProviderConfigProperty();
        piPollInBrowser.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piPollInBrowser.setName(Const.CONFIG_POLL_IN_BROWSER);
        piPollInBrowser.setLabel("Poll in browser");
        piPollInBrowser.setDefaultValue(false);
        piPollInBrowser.setHelpText(
                "Enable this to do the polling for accepted push requests in the user's browser. " +
                        "When enabled, the login page does not refresh when checking for successful push authentication. " +
                        "NOTE: privacyIDEA has to be reachable from the user's browser and a valid SSL certificate has to be in place.");
        configProperties.add(piPollInBrowser);

        ProviderConfigProperty piPollInBrowserUrl = new ProviderConfigProperty();
        piPollInBrowserUrl.setType(ProviderConfigProperty.STRING_TYPE);
        piPollInBrowserUrl.setName(Const.CONFIG_POLL_IN_BROWSER_URL);
        piPollInBrowserUrl.setLabel("Url for poll in browser");
        piPollInBrowserUrl.setHelpText("Optional. If poll in browser should use a deviating URL, set it here. Otherwise, the general URL will be used.");
        configProperties.add(piPollInBrowserUrl);

        ProviderConfigProperty piPushTokenInterval = new ProviderConfigProperty();
        piPushTokenInterval.setType(ProviderConfigProperty.STRING_TYPE);
        piPushTokenInterval.setName(Const.CONFIG_PUSH_INTERVAL);
        piPushTokenInterval.setLabel("Push refresh interval");
        piPushTokenInterval.setHelpText(
                "Set the refresh interval for push tokens in seconds. Use a comma separated list. The last entry will be repeated.");
        configProperties.add(piPushTokenInterval);

        ProviderConfigProperty piDoLog = new ProviderConfigProperty();
        piDoLog.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piDoLog.setName(Const.CONFIG_ENABLE_LOG);
        piDoLog.setLabel("Enable logging");
        piDoLog.setHelpText("If enabled, log messages will be written to the keycloak server logfile.");
        piDoLog.setDefaultValue("false");
        configProperties.add(piDoLog);
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