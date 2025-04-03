/*
 * Copyright 2023 NetKnights GmbH - nils.behlen@netknights.it
 * lukas.matusiewicz@netknights.it
 * - Modified
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.privacyidea.authenticator.Const.CONFIG_CUSTOM_HEADERS;
import static org.privacyidea.authenticator.Const.CONFIG_ENABLE_LOG;
import static org.privacyidea.authenticator.Const.CONFIG_EXCLUDED_GROUPS;
import static org.privacyidea.authenticator.Const.CONFIG_FORWARDED_HEADERS;
import static org.privacyidea.authenticator.Const.CONFIG_FORWARD_CLIENT_IP;
import static org.privacyidea.authenticator.Const.CONFIG_INCLUDED_GROUPS;
import static org.privacyidea.authenticator.Const.CONFIG_OTP_LENGTH;
import static org.privacyidea.authenticator.Const.CONFIG_POLL_IN_BROWSER;
import static org.privacyidea.authenticator.Const.CONFIG_POLL_IN_BROWSER_URL;
import static org.privacyidea.authenticator.Const.CONFIG_REALM;
import static org.privacyidea.authenticator.Const.CONFIG_SEND_PASSWORD;
import static org.privacyidea.authenticator.Const.CONFIG_SEND_STATIC_PASS;
import static org.privacyidea.authenticator.Const.CONFIG_SERVER;
import static org.privacyidea.authenticator.Const.CONFIG_SERVICE_ACCOUNT;
import static org.privacyidea.authenticator.Const.CONFIG_SERVICE_PASS;
import static org.privacyidea.authenticator.Const.CONFIG_SERVICE_REALM;
import static org.privacyidea.authenticator.Const.CONFIG_STATIC_PASS;
import static org.privacyidea.authenticator.Const.CONFIG_TRIGGER_CHALLENGE;
import static org.privacyidea.authenticator.Const.CONFIG_VERIFY_SSL;
import static org.privacyidea.authenticator.Const.POLLING_INTERVALS;
import static org.privacyidea.authenticator.Const.TRUE;


public class Configuration
{
    private final String serverURL;
    private final String realm;
    private final boolean doSSLVerify;
    private final boolean doTriggerChallenge;
    private final boolean doSendPassword;
    private final boolean doSendStaticPass;
    private final String staticPass;
    private final String serviceAccountName;
    private final String serviceAccountPass;
    private final String serviceAccountRealm;
    private final List<String> excludedGroups = new ArrayList<>();
    private final List<String> includedGroups = new ArrayList<>();
    private final List<String> forwardedHeaders = new ArrayList<>();
    private final boolean forwardClientIP;
    private final String otpLength;
    private final boolean doLog;
    private final boolean pollInBrowser;
    private final String pollInBrowserUrl;
    private final List<Integer> pollingInterval = new ArrayList<>();
    private final int configHash;
    private final Map<String, String> customHeaders = new HashMap<>();
    private final int httpTimeoutMs;

    public Configuration(Map<String, String> configMap)
    {
        this.configHash = configMap.hashCode();
        this.serverURL = configMap.get(CONFIG_SERVER);
        this.realm = configMap.get(CONFIG_REALM) == null ? "" : configMap.get(CONFIG_REALM);
        this.doSSLVerify = configMap.get(CONFIG_VERIFY_SSL) != null && configMap.get(CONFIG_VERIFY_SSL).equals(TRUE);
        this.doTriggerChallenge = configMap.get(CONFIG_TRIGGER_CHALLENGE) != null && configMap.get(CONFIG_TRIGGER_CHALLENGE).equals(TRUE);
        this.serviceAccountName = configMap.get(CONFIG_SERVICE_ACCOUNT) == null ? "" : configMap.get(CONFIG_SERVICE_ACCOUNT);
        this.serviceAccountPass = configMap.get(CONFIG_SERVICE_PASS) == null ? "" : configMap.get(CONFIG_SERVICE_PASS);
        this.serviceAccountRealm = configMap.get(CONFIG_SERVICE_REALM) == null ? "" : configMap.get(CONFIG_SERVICE_REALM);
        this.staticPass = configMap.get(CONFIG_STATIC_PASS) == null ? "" : configMap.get(CONFIG_STATIC_PASS);
        this.forwardClientIP = configMap.get(CONFIG_FORWARD_CLIENT_IP) != null && configMap.get(CONFIG_FORWARD_CLIENT_IP).equals(TRUE);
        this.otpLength = configMap.get(CONFIG_OTP_LENGTH) == null ? "" : configMap.get(CONFIG_OTP_LENGTH);
        this.pollInBrowser = (configMap.get(CONFIG_POLL_IN_BROWSER) != null && configMap.get(CONFIG_POLL_IN_BROWSER).equals(TRUE));
        this.pollInBrowserUrl = configMap.get(CONFIG_POLL_IN_BROWSER_URL) == null ? "" : configMap.get(CONFIG_POLL_IN_BROWSER_URL);
        this.doSendPassword = configMap.get(CONFIG_SEND_PASSWORD) != null && configMap.get(CONFIG_SEND_PASSWORD).equals(TRUE);
        this.doSendStaticPass = configMap.get(CONFIG_SEND_STATIC_PASS) != null && configMap.get(CONFIG_SEND_STATIC_PASS).equals(TRUE);
        this.doLog = configMap.get(CONFIG_ENABLE_LOG) != null && configMap.get(CONFIG_ENABLE_LOG).equals(TRUE);

        String excludedGroupsStr = configMap.get(CONFIG_EXCLUDED_GROUPS);
        if (excludedGroupsStr != null)
        {
            this.excludedGroups.addAll(Arrays.asList(excludedGroupsStr.split(",")));
        }

        String includedGroupsStr = configMap.get(CONFIG_INCLUDED_GROUPS);
        if (includedGroupsStr != null)
        {
            this.includedGroups.addAll(Arrays.asList(includedGroupsStr.split(",")));
        }

        String forwardedHeadersStr = configMap.get(CONFIG_FORWARDED_HEADERS);
        if (forwardedHeadersStr != null)
        {
            this.forwardedHeaders.addAll(Arrays.asList(forwardedHeadersStr.split(",")));
        }

        this.pollingInterval.addAll(POLLING_INTERVALS);

        String entry = configMap.get(CONFIG_CUSTOM_HEADERS);
        if (entry != null && !entry.isEmpty())
        {
            String[] entries = entry.split("##");
            for (String e : entries)
            {
                if (e == null || e.isEmpty())
                {
                    continue;
                }
                String[] keyValue = e.split("=");
                if (keyValue.length == 2)
                {
                    customHeaders.put(keyValue[0], keyValue[1]);
                }
            }
        }

        this.httpTimeoutMs = Integer.parseInt(configMap.getOrDefault("httpTimeoutMs", "10000"));
    }

    int configHash()
    {
        return configHash;
    }

    String serverURL()
    {
        return serverURL;
    }

    String realm()
    {
        return realm;
    }

    boolean sslVerify()
    {
        return doSSLVerify;
    }

    boolean triggerChallenge()
    {
        return doTriggerChallenge;
    }

    boolean sendStaticPass()
    {
        return doSendStaticPass;
    }

    String staticPass()
    {
        return staticPass;
    }

    String serviceAccountName()
    {
        return serviceAccountName;
    }

    String serviceAccountPass()
    {
        return serviceAccountPass;
    }

    String serviceAccountRealm()
    {
        return serviceAccountRealm;
    }

    List<String> excludedGroups()
    {
        return excludedGroups;
    }

    List<String> includedGroups()
    {
        return includedGroups;
    }

    List<String> forwardedHeaders()
    {
        return forwardedHeaders;
    }

    boolean forwardClientIP()
    {
        return forwardClientIP;
    }

    String otpLength()
    {
        return otpLength;
    }

    boolean pollInBrowser()
    {
        return pollInBrowser;
    }

    String pollInBrowserUrl()
    {
        return pollInBrowserUrl;
    }

    List<Integer> pollingInterval()
    {
        return pollingInterval;
    }

    boolean doLog()
    {
        return doLog;
    }

    boolean sendPassword()
    {
        return doSendPassword;
    }

    Map<String, String> customHeaders()
    {
        return customHeaders;
    }

    public int httpTimeoutMs()
    {
        return httpTimeoutMs;
    }
}