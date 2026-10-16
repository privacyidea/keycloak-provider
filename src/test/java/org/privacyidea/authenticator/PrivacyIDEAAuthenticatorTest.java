/*
 * Copyright 2026 NetKnights GmbH - nils.behlen@netknights.it
 *
 * SPDX-License-Identifier: Apache-2.0
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

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.ext.RuntimeDelegate;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.credential.CredentialInput;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.privacyidea.PIConstants.AUTH_FORM;
import static org.privacyidea.PIConstants.AUTH_FORM_RESULT;
import static org.privacyidea.PIConstants.PASSWORD;
import static org.privacyidea.PIConstants.USERNAME;

/**
 * Unit tests for the remember device gate of {@link PrivacyIDEAAuthenticator}: it needs a password check earlier in
 * the same login, which this provider notes after checking the password on its own login form.
 */
public class PrivacyIDEAAuthenticatorTest
{
    private PrivacyIDEAAuthenticator authenticator;
    private AuthenticationSessionModel authenticationSession;
    private AuthenticationFlowContext context;
    private Pair pair;

    @BeforeClass
    public static void setupJaxRs()
    {
        // Cookie needs a JAX-RS implementation, which Keycloak provides at runtime but the tests do not have
        RuntimeDelegate.setInstance(mock(RuntimeDelegate.class));
    }

    @Before
    public void setup()
    {
        authenticator = new PrivacyIDEAAuthenticator();
        authenticationSession = mock(AuthenticationSessionModel.class);
        context = mock(AuthenticationFlowContext.class);
        when(context.getAuthenticationSession()).thenReturn(authenticationSession);
        when(context.getSession()).thenReturn(mock(KeycloakSession.class));

        Map<String, String> map = new HashMap<>();
        map.put(Const.CONFIG_REMEMBER_DEVICE, "true");
        map.put(Const.CONFIG_API_KEY, "key");
        Configuration config = new Configuration(map);
        RememberDevice rememberDevice = new RememberDevice(config, authenticator);
        rememberDevice.cacheServerCapability(Boolean.TRUE);
        pair = new Pair(mock(PrivacyIDEA.class), config, rememberDevice);
    }

    @Test
    public void passwordCheckedByKeycloakFormAllowsRememberDevice()
    {
        when(authenticationSession.getAuthNote(AuthenticationManager.PASSWORD_VALIDATED)).thenReturn("true");

        assertTrue(authenticator.rememberDeviceAllowed(context, pair, new HashMap<>()));
    }

    @Test
    public void passwordCheckedByThisProviderAllowsRememberDeviceInALaterAuthenticate()
    {
        when(authenticationSession.getAuthNote(Const.NOTE_PASSWORD_CHECKED)).thenReturn("true");

        assertTrue(authenticator.rememberDeviceAllowed(context, pair, new HashMap<>()));
    }

    @Test
    public void noPasswordCheckMeansNoRememberDevice()
    {
        assertFalse(authenticator.rememberDeviceAllowed(context, pair, new HashMap<>()));
    }

    @Test
    public void passwordCheckByThisProviderIsNotedForALaterAuthenticate()
    {
        authenticator.action(usernamePasswordPost(true));

        verify(authenticationSession).setAuthNote(Const.NOTE_PASSWORD_CHECKED, "true");
    }

    @Test
    public void wrongPasswordIsNotNoted()
    {
        authenticator.action(usernamePasswordPost(false));

        verify(authenticationSession, never()).setAuthNote(eq(Const.NOTE_PASSWORD_CHECKED), anyString());
    }

    @Test
    public void recognizedDeviceIsNotedAsAuthenticationMethod()
    {
        assertTrue(authenticator.isRememberedDevice(requestWithCookie(), pairAnswering(true), user(), new HashMap<>()));

        verify(authenticationSession).setUserSessionNote("privacyidea_authentication_method", "remember_device");
    }

    @Test
    public void unrecognizedDeviceKeepsTheAuthenticationMethod()
    {
        assertFalse(authenticator.isRememberedDevice(requestWithCookie(), pairAnswering(false), user(), new HashMap<>()));

        verify(authenticationSession, never()).setUserSessionNote(eq("privacyidea_authentication_method"), anyString());
    }

    private AuthenticationFlowContext requestWithCookie()
    {
        Cookie cookie = mock(Cookie.class);
        when(cookie.getValue()).thenReturn("series:1");
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(httpHeaders.getCookies()).thenReturn(Map.of(RememberDevice.COOKIE_NAME, cookie));
        HttpRequest httpRequest = mock(HttpRequest.class);
        when(httpRequest.getHttpHeaders()).thenReturn(httpHeaders);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        return context;
    }

    private Pair pairAnswering(boolean recognized)
    {
        PIResponse response = new PIResponse();
        response.value = recognized;
        PrivacyIDEA privacyIDEA = mock(PrivacyIDEA.class);
        when(privacyIDEA.rememberDeviceCheck(anyString(), any())).thenReturn(response);
        return new Pair(privacyIDEA, pair.configuration(), pair.rememberDevice());
    }

    private UserModel user()
    {
        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn("rd-user");
        return user;
    }

    /**
     * A post of the provider's own username and password form, with the password check answering passwordValid.
     */
    private AuthenticationFlowContext usernamePasswordPost(boolean passwordValid)
    {
        Map<String, String> configMap = new HashMap<>();
        configMap.put(Const.CONFIG_SERVER, "https://pi.example");
        AuthenticatorConfigModel authenticatorConfig = new AuthenticatorConfigModel();
        authenticatorConfig.setConfig(configMap);
        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test");
        when(context.getRealm()).thenReturn(realm);

        AuthenticationForm piForm = new AuthenticationForm(new Configuration(configMap));
        piForm.setMode(Mode.USERNAMEPASSWORD);
        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(AUTH_FORM_RESULT, new AuthenticationFormResult().toString());
        formData.add(AUTH_FORM, piForm.toString());
        formData.add(USERNAME, "rd-user");
        formData.add(PASSWORD, "secret");
        HttpRequest httpRequest = mock(HttpRequest.class);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(context.form()).thenReturn(mock(LoginFormsProvider.class));

        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext keycloakContext = mock(KeycloakContext.class);
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(httpHeaders.getRequestHeaders()).thenReturn(new MultivaluedHashMap<>());
        when(keycloakContext.getRequestHeaders()).thenReturn(httpHeaders);
        when(session.getContext()).thenReturn(keycloakContext);
        UserModel user = mock(UserModel.class);
        SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
        when(credentialManager.isValid(any(CredentialInput.class))).thenReturn(passwordValid);
        when(user.credentialManager()).thenReturn(credentialManager);
        UserProvider users = mock(UserProvider.class);
        when(users.getUserByUsername(realm, "rd-user")).thenReturn(user);
        when(session.users()).thenReturn(users);
        when(context.getSession()).thenReturn(session);
        return context;
    }
}
