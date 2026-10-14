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

import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.ext.RuntimeDelegate;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.privacyidea.IPILogger;
import org.privacyidea.PrivacyIDEA;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.privacyidea.PIConstants.HEADER_COOKIE;
import static org.privacyidea.PIConstants.HEADER_X_API_KEY;

/**
 * Unit tests for {@link RememberDevice}: parsing privacyIDEA's Set-Cookie, the cookie written to the browser and the
 * capability cache, which must fail closed.
 */
public class RememberDeviceTest
{
    private AtomicLong now;
    private PrivacyIDEA privacyIDEA;

    @BeforeClass
    public static void setupJaxRs()
    {
        // NewCookie needs a JAX-RS implementation, which Keycloak provides at runtime but the tests do not have
        RuntimeDelegate.setInstance(mock(RuntimeDelegate.class));
    }

    @Before
    public void setup()
    {
        now = new AtomicLong(1_000_000L);
        privacyIDEA = mock(PrivacyIDEA.class);
    }

    private RememberDevice rememberDevice(boolean enabled, String apiKey)
    {
        Map<String, String> map = new HashMap<>();
        map.put(Const.CONFIG_REMEMBER_DEVICE, String.valueOf(enabled));
        if (apiKey != null)
        {
            map.put(Const.CONFIG_API_KEY, apiKey);
        }
        return new RememberDevice(new Configuration(map), new NoopLogger(), now::get);
    }

    @Test
    public void configuredOnlyWithSwitchAndApiKey()
    {
        assertTrue(rememberDevice(true, "key").isConfigured());
        assertFalse(rememberDevice(false, "key").isConfigured());
        assertFalse(rememberDevice(true, null).isConfigured());
        assertFalse(rememberDevice(true, " ").isConfigured());
    }

    @Test
    public void notConfiguredNeverAsksPrivacyIDEA()
    {
        RememberDevice rd = rememberDevice(true, null);
        assertFalse(rd.isServerCapable(privacyIDEA, new HashMap<>()));
        verify(privacyIDEA, never()).getRememberDeviceCapability(anyMap());
    }

    @Test
    public void capabilityIsCachedAndSentWithApiKey()
    {
        RememberDevice rd = rememberDevice(true, "key");
        when(privacyIDEA.getRememberDeviceCapability(anyMap())).thenAnswer(invocation -> {
            Map<String, String> headers = invocation.getArgument(0);
            assertEquals("key", headers.get(HEADER_X_API_KEY));
            return Boolean.TRUE;
        });
        Map<String, String> headers = new HashMap<>();

        assertTrue(rd.isServerCapable(privacyIDEA, headers));
        assertTrue(rd.isServerCapable(privacyIDEA, headers));
        verify(privacyIDEA, times(1)).getRememberDeviceCapability(anyMap());
        // The caller's headers stay without the API key
        assertFalse(headers.containsKey(HEADER_X_API_KEY));

        now.addAndGet(RememberDevice.CAPABILITY_TTL_MILLIS);
        assertTrue(rd.isServerCapable(privacyIDEA, headers));
        verify(privacyIDEA, times(2)).getRememberDeviceCapability(anyMap());
    }

    @Test
    public void inconclusiveCapabilityFailsClosedAndIsRetriedLater()
    {
        RememberDevice rd = rememberDevice(true, "key");
        when(privacyIDEA.getRememberDeviceCapability(anyMap())).thenReturn(null);

        assertFalse(rd.isServerCapable(privacyIDEA, new HashMap<>()));
        assertFalse(rd.isServerCapable(privacyIDEA, new HashMap<>()));
        verify(privacyIDEA, times(1)).getRememberDeviceCapability(anyMap());

        now.addAndGet(RememberDevice.CAPABILITY_UNKNOWN_TTL_MILLIS);
        when(privacyIDEA.getRememberDeviceCapability(anyMap())).thenReturn(Boolean.TRUE);
        assertTrue(rd.isServerCapable(privacyIDEA, new HashMap<>()));
    }

    @Test
    public void inconclusiveProbeKeepsEarlierAnswer()
    {
        RememberDevice rd = rememberDevice(true, "key");
        rd.cacheServerCapability(Boolean.FALSE);
        now.addAndGet(RememberDevice.CAPABILITY_TTL_MILLIS);
        when(privacyIDEA.getRememberDeviceCapability(anyMap())).thenReturn(null);

        assertFalse(rd.isServerCapable(privacyIDEA, new HashMap<>()));
    }

    @Test
    public void recognitionDataCarriesApiKeyAndCookie()
    {
        Map<String, String> headers = new LinkedHashMap<>();
        rememberDevice(true, "key").addRecognitionData(headers, "series:2");

        assertEquals("key", headers.get(HEADER_X_API_KEY));
        assertEquals("pi_remember_device=series:2", headers.get(HEADER_COOKIE));
    }

    @Test
    public void parseNewCookieWithMaxAge()
    {
        RememberDevice.CookieUpdate update = RememberDevice.parseSetCookie(
                List.of("other=1; Path=/", "pi_remember_device=abc:1; Max-Age=86400; Path=/; Secure; HttpOnly"));

        assertEquals("abc:1", update.value());
        assertEquals(86400, update.maxAge());
        assertFalse(update.isClear());
    }

    @Test
    public void parseCookieWithoutMaxAgeUsesDefault()
    {
        RememberDevice.CookieUpdate update = RememberDevice.parseSetCookie(List.of("pi_remember_device=abc:2"));

        assertEquals("abc:2", update.value());
        assertEquals(RememberDevice.DEFAULT_MAX_AGE_SECONDS, update.maxAge());
    }

    @Test
    public void parseClearedCookie()
    {
        assertTrue(RememberDevice.parseSetCookie(List.of("pi_remember_device=; Max-Age=0; Path=/")).isClear());
        assertTrue(RememberDevice.parseSetCookie(List.of("pi_remember_device=abc:3; Max-Age=0")).isClear());
        assertTrue(RememberDevice.parseSetCookie(List.of("pi_remember_device=abc:3; Max-Age=-1")).isClear());
    }

    @Test
    public void noRememberDeviceCookieMeansKeepTheBrowserCookie()
    {
        assertNull(RememberDevice.parseSetCookie(null));
        assertNull(RememberDevice.parseSetCookie(List.of()));
        assertNull(RememberDevice.parseSetCookie(List.of("pi_remember_device_x=abc", "session=1")));
    }

    @Test
    public void parseMaxAge()
    {
        assertEquals(Integer.valueOf(3600), RememberDevice.parseMaxAge("a=b; max-age=03600; Path=/"));
        assertNull(RememberDevice.parseMaxAge("a=b; Max-Age=soon"));
        assertNull(RememberDevice.parseMaxAge("a=b; Path=/"));
    }

    @Test
    public void browserCookieIsStrictSecureHttpOnlyAndScopedToTheRealm()
    {
        NewCookie cookie = RememberDevice.buildCookie("/realms/master/", new RememberDevice.CookieUpdate("abc:1", 600));

        assertEquals("pi_remember_device", cookie.getName());
        assertEquals("abc:1", cookie.getValue());
        assertEquals("/realms/master/", cookie.getPath());
        assertEquals(600, cookie.getMaxAge());
        assertTrue(cookie.isSecure());
        assertTrue(cookie.isHttpOnly());
        assertEquals(NewCookie.SameSite.STRICT, cookie.getSameSite());
    }

    @Test
    public void clearedBrowserCookieExpiresNow()
    {
        NewCookie cookie = RememberDevice.buildCookie("/realms/master/", new RememberDevice.CookieUpdate("", 600));

        assertEquals("", cookie.getValue());
        assertEquals(0, cookie.getMaxAge());
    }

    private static final class NoopLogger implements IPILogger
    {
        @Override
        public void log(String message) {}

        @Override
        public void error(String message) {}

        @Override
        public void log(Throwable t) {}

        @Override
        public void error(Throwable t) {}
    }
}
