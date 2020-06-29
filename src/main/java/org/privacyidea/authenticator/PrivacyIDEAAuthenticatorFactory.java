package org.privacyidea.authenticator;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;


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
public class PrivacyIDEAAuthenticatorFactory implements org.keycloak.authentication.AuthenticatorFactory, org.keycloak.authentication.ConfigurableAuthenticatorFactory {

    private static final PrivacyIDEAAuthenticator SINGLETON = new PrivacyIDEAAuthenticator();
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public String getId() {
        return Const.PROVIDER_ID;
    }

    @Override
    public org.keycloak.authentication.Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    static {
        ProviderConfigProperty piServerUrl = new ProviderConfigProperty();
        piServerUrl.setType(ProviderConfigProperty.TEXT_TYPE);
        piServerUrl.setName(Const.CONFIG_SERVER);
        piServerUrl.setLabel("URL");
        piServerUrl.setHelpText("The URL of the privacyIDEA server (complete with scheme, host and port like \"https://<piserver>:port\")");
        configProperties.add(piServerUrl);

        ProviderConfigProperty piRealm = new ProviderConfigProperty();
        piRealm.setType(ProviderConfigProperty.STRING_TYPE);
        piRealm.setName(Const.CONFIG_REALM);
        piRealm.setLabel("Realm");
        piRealm.setHelpText("Select the realm where your users are stored. Leave empty for default.");
        configProperties.add(piRealm);

        ProviderConfigProperty piVerifySSL = new ProviderConfigProperty();
        piVerifySSL.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piVerifySSL.setName(Const.CONFIG_VERIFYSSL);
        piVerifySSL.setLabel("Verify SSL");
        piVerifySSL.setHelpText("Do not uncheck this in productive environment");
        configProperties.add(piVerifySSL);

        ProviderConfigProperty piDoTriggerChallenge = new ProviderConfigProperty();
        piDoTriggerChallenge.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piDoTriggerChallenge.setName(Const.CONFIG_DOTRIGGERCHALLENGE);
        piDoTriggerChallenge.setLabel("Enable trigger challenge");
        piDoTriggerChallenge.setHelpText("Choose if you want to do trigger challenge");
        configProperties.add(piDoTriggerChallenge);

        ProviderConfigProperty piServiceAccount = new ProviderConfigProperty();
        piServiceAccount.setType(ProviderConfigProperty.STRING_TYPE);
        piServiceAccount.setName(Const.CONFIG_SERVICEACCOUNT);
        piServiceAccount.setLabel("Service account");
        piServiceAccount.setHelpText("Username of the service account. Needed for trigger challenge, token enrollment and push tokens.");
        configProperties.add(piServiceAccount);

        ProviderConfigProperty piServicePass = new ProviderConfigProperty();
        piServicePass.setType(ProviderConfigProperty.PASSWORD);
        piServicePass.setName(Const.CONFIG_SERVICEPASS);
        piServicePass.setLabel("Service account password");
        piServicePass.setHelpText("Password of the service account. Needed for trigger challenge, token enrollment and push tokens");
        configProperties.add(piServicePass);

        ProviderConfigProperty piExcludeGroups = new ProviderConfigProperty();
        piExcludeGroups.setType(ProviderConfigProperty.STRING_TYPE);
        piExcludeGroups.setName(Const.CONFIG_EXCLUDEGROUPS);
        piExcludeGroups.setLabel("Exclude groups");
        piExcludeGroups.setHelpText("You can select groups, which will not do 2FA. Enter the group names and separate them with comma e.g. 'group1,group2'");
        configProperties.add(piExcludeGroups);

        ProviderConfigProperty piEnrollToken = new ProviderConfigProperty();
        piEnrollToken.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piEnrollToken.setName(Const.CONFIG_ENROLLTOKEN);
        piEnrollToken.setLabel("Enable token enrollment");
        piEnrollToken.setHelpText("If enabled, the user gets a token enrolled automatically for them, if they do not have one yet. The Service account is needed");
        piEnrollToken.setDefaultValue("false");
        configProperties.add(piEnrollToken);

        List<String> tokenTypes = new ArrayList<>();
        tokenTypes.add("HOTP");
        tokenTypes.add("TOTP");
        ProviderConfigProperty piTokenType = new ProviderConfigProperty();
        piTokenType.setType(ProviderConfigProperty.LIST_TYPE);
        piTokenType.setName(Const.CONFIG_ENROLLTOKENTYPE);
        piTokenType.setLabel("Enrollment Token type");
        piTokenType.setHelpText("Select the token type that users can enroll, if they do not have a token yet. Service account is needed");
        piTokenType.setOptions(tokenTypes);
        piTokenType.setDefaultValue("HOTP");
        configProperties.add(piTokenType);

        ProviderConfigProperty piPushTokenInterval = new ProviderConfigProperty();
        piPushTokenInterval.setType(ProviderConfigProperty.STRING_TYPE);
        piPushTokenInterval.setName(Const.CONFIG_PUSHTOKENINTERVAL);
        piPushTokenInterval.setLabel("Refresh interval for push tokens");
        piPushTokenInterval.setHelpText("Set the refresh interval for push tokens in seconds. Use a comma separated list. The last entry will be repeated.");
        configProperties.add(piPushTokenInterval);
    }

    @Override
    public String getHelpText() {
        return "Authenticate the second factor against privacyIDEA.";
    }

    @Override
    public String getDisplayType() {
        return "privacyIDEA";
    }

    @Override
    public String getReferenceCategory() {
        return "privacyIDEA";
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
