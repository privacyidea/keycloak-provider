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

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class privacyIDEAAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "privacyidea-authenticator";
    private static final privacyIDEAAuthenticator SINGLETON = new privacyIDEAAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
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

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {

        ProviderConfigProperty piServerUrl = new ProviderConfigProperty();
        piServerUrl.setType(ProviderConfigProperty.STRING_TYPE);
        piServerUrl.setName("piserver");
        piServerUrl.setLabel("URL");
        piServerUrl.setHelpText("The URL to the privacyIDEA server");
        configProperties.add(piServerUrl);

        ProviderConfigProperty piRealm = new ProviderConfigProperty();
        piRealm.setType(ProviderConfigProperty.STRING_TYPE);
        piRealm.setName("pirealm");
        piRealm.setLabel("Realm");
        piRealm.setHelpText("Select the realm where your users are stored. Leave empty for default.");
        configProperties.add(piRealm);

        ProviderConfigProperty piVerifySSL = new ProviderConfigProperty();
        piVerifySSL.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piVerifySSL.setName("piverifyssl");
        piVerifySSL.setLabel("Verify SSL");
        piVerifySSL.setHelpText("Do not uncheck this in productive environment");
        configProperties.add(piVerifySSL);

        ProviderConfigProperty piDoTriggerChallenge = new ProviderConfigProperty();
        piDoTriggerChallenge.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        piDoTriggerChallenge.setName("pidotriggerchallenge");
        piDoTriggerChallenge.setLabel("Enable trigger challenge");
        piDoTriggerChallenge.setHelpText("Choose if you want to do trigger challenge");
        configProperties.add(piDoTriggerChallenge);

        ProviderConfigProperty piServiceAccount = new ProviderConfigProperty();
        piServiceAccount.setType(ProviderConfigProperty.STRING_TYPE);
        piServiceAccount.setName("piserviceaccount");
        piServiceAccount.setLabel("Service account");
        piServiceAccount.setHelpText("Username of the service account. Only needed, if trigger challenge is enabled.");
        configProperties.add(piServiceAccount);

        ProviderConfigProperty piServicePass = new ProviderConfigProperty();
        piServicePass.setType(ProviderConfigProperty.PASSWORD);
        piServicePass.setName("piservicepass");
        piServicePass.setLabel("Service account password");
        piServicePass.setHelpText("Password of the service account. Only needed, if trigger challenge is enabled.");
        configProperties.add(piServicePass);


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
