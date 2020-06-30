package org.privacyidea.authenticator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

class Configuration {

    private final String serverURL;
    private final String realm;
    private final boolean doSSLVerify;
    private final boolean doTriggerChallenge;
    private final String serviceAccountName;
    private final String serviceAccountPass;
    private final List<String> excludedGroups = new ArrayList<>();
    private final boolean doEnrollToken;
    private final boolean doLog;
    private final String enrollingTokenType;
    private final List<Integer> pushtokenPollingInterval = new ArrayList<>();

    Configuration(Map<String, String> configMap) {
        serverURL = configMap.get(Const.CONFIG_SERVER);
        realm = configMap.get(Const.CONFIG_REALM) == null ? "" : configMap.get(Const.CONFIG_REALM);
        doSSLVerify = configMap.get(Const.CONFIG_VERIFYSSL) != null && configMap.get(Const.CONFIG_VERIFYSSL).equals(Const.TRUE);
        doTriggerChallenge = configMap.get(Const.CONFIG_DOTRIGGERCHALLENGE) != null && configMap.get(Const.CONFIG_DOTRIGGERCHALLENGE).equals(Const.TRUE);
        serviceAccountName = configMap.get(Const.CONFIG_SERVICEACCOUNT) == null ? "" : configMap.get(Const.CONFIG_SERVICEACCOUNT);
        serviceAccountPass = (configMap.get(Const.CONFIG_SERVICEPASS) == null) ? "" : configMap.get(Const.CONFIG_SERVICEPASS);
        doEnrollToken = configMap.get(Const.CONFIG_ENROLLTOKEN) != null && configMap.get(Const.CONFIG_ENROLLTOKEN).equals(Const.TRUE);
        enrollingTokenType = configMap.get(Const.CONFIG_ENROLLTOKENTYPE) == null ? "" : configMap.get(Const.CONFIG_ENROLLTOKENTYPE);

        doLog = configMap.get(Const.CONFIG_DO_LOG) != null && configMap.get(Const.CONFIG_DO_LOG).equals(Const.TRUE);

        String excludedGroupsStr = configMap.get(Const.CONFIG_EXCLUDEGROUPS);
        if (excludedGroupsStr != null) {
            excludedGroups.addAll(Arrays.asList(excludedGroupsStr.split(",")));
        }

        // Set default, overwrite if configured
        pushtokenPollingInterval.addAll(Const.DEFAULT_POLLING_ARRAY);
        String s = configMap.get(Const.CONFIG_PUSHTOKENINTERVAL);
        if (s != null) {
            List<String> strPollingIntervals = Arrays.asList(s.split(","));
            if (!strPollingIntervals.isEmpty()) {
                pushtokenPollingInterval.clear();
                for (String str : strPollingIntervals) {
                    try {
                        pushtokenPollingInterval.add(Integer.parseInt(str));
                    } catch (NumberFormatException e) {
                        pushtokenPollingInterval.add(Const.DEFAULT_POLLING_INTERVAL);
                    }
                }
            }
        }
    }

    String getServerURL() {
        return serverURL;
    }

    String getRealm() {
        return realm;
    }

    boolean doSSLVerify() {
        return doSSLVerify;
    }

    boolean doTriggerChallenge() {
        return doTriggerChallenge;
    }

    String getServiceAccountName() {
        return serviceAccountName;
    }

    String getServiceAccountPass() {
        return serviceAccountPass;
    }

    List<String> getExcludedGroups() {
        return excludedGroups;
    }

    boolean doEnrollToken() {
        return doEnrollToken;
    }

    String getEnrollingTokenType() {
        return enrollingTokenType;
    }

    List<Integer> getPushtokenPollingInterval() {
        return pushtokenPollingInterval;
    }

    public boolean doLog() {
        return doLog;
    }
}
