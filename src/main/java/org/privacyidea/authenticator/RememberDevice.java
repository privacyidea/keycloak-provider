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
import jakarta.ws.rs.core.NewCookie;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.utils.StringUtil;
import org.privacyidea.IPILogger;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;

import static org.privacyidea.PIConstants.HEADER_COOKIE;
import static org.privacyidea.PIConstants.HEADER_X_API_KEY;

/**
 * "Remember this device": relays privacyIDEA's pi_remember_device cookie between privacyIDEA and the browser and
 * caches whether privacyIDEA offers the feature to this client. Follows the RememberMeManager of the Shibboleth plugin.
 * There is one instance per realm configuration, so a changed configuration starts with an empty capability cache.
 */
public class RememberDevice
{
    static final String COOKIE_NAME = "pi_remember_device";
    // Used only when privacyIDEA's Set-Cookie carries no Max-Age: 7 days
    static final int DEFAULT_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
    // A definitive answer of GET /validate/capabilities is trusted for 15 minutes, so a policy change on the server is
    // picked up without a restart. An inconclusive probe (server unreachable or too old) is retried after 2 minutes,
    // so a down server does not delay every login by the HTTP timeout.
    static final long CAPABILITY_TTL_MILLIS = 15 * 60 * 1000L;
    static final long CAPABILITY_UNKNOWN_TTL_MILLIS = 2 * 60 * 1000L;

    private final Configuration config;
    private final IPILogger logger;
    private final LongSupplier clock;
    private volatile Boolean serverCapable;
    private volatile long capabilityResolvedAt;
    private volatile long capabilityProbedAt;

    public RememberDevice(Configuration config, IPILogger logger)
    {
        this(config, logger, System::currentTimeMillis);
    }

    RememberDevice(Configuration config, IPILogger logger, LongSupplier clock)
    {
        this.config = config;
        this.logger = logger;
        this.clock = clock;
    }

    /**
     * @return whether the feature is turned on and an API key is set. Only then is anything sent to privacyIDEA.
     */
    boolean isConfigured()
    {
        return config.isRememberDeviceEnabled() && StringUtil.isNotBlank(config.apiKey());
    }

    /**
     * Whether privacyIDEA offers remember device to this client. Asks GET /validate/capabilities if there is no cached
     * answer or it has expired. Fails closed: false until privacyIDEA answered true.
     *
     * @param privacyIDEA the privacyIDEA instance of the realm
     * @param headers     the headers of the current request, the API key is added to a copy
     * @return true if privacyIDEA advertises remember device for this client
     */
    boolean isServerCapable(PrivacyIDEA privacyIDEA, Map<String, String> headers)
    {
        if (!isConfigured())
        {
            return false;
        }
        if (!isCapabilityResolved())
        {
            Map<String, String> capabilityHeaders = new LinkedHashMap<>(headers);
            addApiKey(capabilityHeaders);
            Boolean capability = privacyIDEA.getRememberDeviceCapability(capabilityHeaders);
            cacheServerCapability(capability);
            if (capability == null)
            {
                logger.error("Remember device: could not get the capability from privacyIDEA (unreachable or older than 3.14). " +
                             "Remember device stays inactive for now.");
            }
            else if (!capability)
            {
                logger.log("Remember device: privacyIDEA does not offer remember device to this API client. " +
                           "Check the 'remember_device' policy in privacyIDEA.");
            }
            else
            {
                logger.log("Remember device: privacyIDEA offers remember device to this API client.");
            }
        }
        return Boolean.TRUE.equals(serverCapable);
    }

    boolean isCapabilityResolved()
    {
        long now = clock.getAsLong();
        if (serverCapable != null && (now - capabilityResolvedAt) < CAPABILITY_TTL_MILLIS)
        {
            return true;
        }
        return capabilityProbedAt > 0 && (now - capabilityProbedAt) < CAPABILITY_UNKNOWN_TTL_MILLIS;
    }

    /**
     * Caches a capability answer. Null (inconclusive) only stamps the probe time and keeps an earlier answer.
     */
    void cacheServerCapability(Boolean capability)
    {
        long now = clock.getAsLong();
        capabilityProbedAt = now;
        if (capability != null)
        {
            serverCapable = capability;
            capabilityResolvedAt = now;
        }
    }

    /**
     * Adds the API key, which identifies this client to privacyIDEA. Only for requests that need it: the capability
     * check, the recognition and an opt-in on /validate/check. A plain login sends no key, so a wrong or revoked key
     * cannot break it.
     */
    void addApiKey(Map<String, String> headers)
    {
        headers.put(HEADER_X_API_KEY, config.apiKey());
    }

    /**
     * Adds the API key and the stored cookie for POST /validate/remember_device.
     */
    void addRecognitionData(Map<String, String> headers, String cookieValue)
    {
        addApiKey(headers);
        headers.put(HEADER_COOKIE, COOKIE_NAME + "=" + cookieValue);
    }

    /**
     * @return the value of the pi_remember_device cookie sent by the browser, or null
     */
    static String readCookie(AuthenticationFlowContext context)
    {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(COOKIE_NAME);
        return cookie == null ? null : cookie.getValue();
    }

    /**
     * Applies privacyIDEA's Set-Cookie to the browser: stores a new or rotated value with privacyIDEA's Max-Age, or
     * removes the cookie if privacyIDEA cleared it. Without a pi_remember_device Set-Cookie the browser cookie is kept,
     * for example on a duplicate request within privacyIDEA's grace window or on a shared browser.
     *
     * @param context    the flow context of the current request
     * @param piResponse the response of privacyIDEA, may be null
     */
    void relay(AuthenticationFlowContext context, PIResponse piResponse)
    {
        if (!isConfigured() || piResponse == null)
        {
            return;
        }
        CookieUpdate update = parseSetCookie(piResponse.setCookieHeaders);
        if (update == null)
        {
            return;
        }
        String path = cookiePath(context);
        context.getSession().getContext().getHttpResponse().setCookieIfAbsent(buildCookie(path, update));
        if (update.isClear())
        {
            logger.log("Remember device: privacyIDEA cleared the cookie, removing it from the browser.");
        }
        else
        {
            logger.log("Remember device: stored the cookie from privacyIDEA in the browser.");
        }
    }

    /**
     * The value and lifetime privacyIDEA sent for the cookie. A max age of 0 or less clears it.
     */
    record CookieUpdate(String value, int maxAge)
    {
        boolean isClear()
        {
            return value.isEmpty() || maxAge <= 0;
        }
    }

    /**
     * @param setCookieHeaders the Set-Cookie headers of a privacyIDEA response
     * @return the update for the pi_remember_device cookie, or null if privacyIDEA did not send one
     */
    static CookieUpdate parseSetCookie(List<String> setCookieHeaders)
    {
        if (setCookieHeaders == null)
        {
            return null;
        }
        String prefix = COOKIE_NAME + "=";
        for (String header : setCookieHeaders)
        {
            if (header == null || !header.startsWith(prefix))
            {
                continue;
            }
            String afterName = header.substring(prefix.length());
            int semicolon = afterName.indexOf(';');
            String value = (semicolon >= 0 ? afterName.substring(0, semicolon) : afterName).trim();
            Integer maxAge = parseMaxAge(header);
            return new CookieUpdate(value, maxAge != null ? maxAge : DEFAULT_MAX_AGE_SECONDS);
        }
        return null;
    }

    /**
     * @return the Max-Age attribute of a Set-Cookie header in seconds, or null if it is missing or not a number
     */
    static Integer parseMaxAge(String header)
    {
        for (String attribute : header.split(";"))
        {
            String token = attribute.trim();
            if (token.regionMatches(true, 0, "Max-Age=", 0, "Max-Age=".length()))
            {
                try
                {
                    return Integer.parseInt(token.substring("Max-Age=".length()).trim());
                }
                catch (NumberFormatException e)
                {
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * The cookie is scoped to the Keycloak realm, so each realm keeps its own. SameSite=Strict keeps it off cross-site
     * requests; the password POST that leads to the recognition is same-site and carries it.
     */
    static NewCookie buildCookie(String path, CookieUpdate update)
    {
        return new NewCookie.Builder(COOKIE_NAME).value(update.isClear() ? "" : update.value())
                                                 .path(path)
                                                 .maxAge(update.isClear() ? 0 : update.maxAge())
                                                 .secure(true)
                                                 .httpOnly(true)
                                                 .sameSite(NewCookie.SameSite.STRICT)
                                                 .build();
    }

    /**
     * @return the path of the realm, for example /realms/master/ or /auth/realms/master/ with a context path
     */
    static String cookiePath(AuthenticationFlowContext context)
    {
        String base = context.getUriInfo().getBaseUri().getPath();
        if (!base.endsWith("/"))
        {
            base = base + "/";
        }
        return base + "realms/" + context.getRealm().getName() + "/";
    }
}
