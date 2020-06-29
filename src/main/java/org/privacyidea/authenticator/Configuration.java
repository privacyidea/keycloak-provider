package org.privacyidea.authenticator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

class Configuration {

    private final String _serverURL;
    private final String _realm;
    private final boolean _doSSLVerify;
    private final boolean _doTriggerChallenge;
    private final String _serviceAccountName;
    private final String _serviceAccountPass;
    private final List<String> _excludedGroups = new ArrayList<>();
    private final boolean _doEnrollToken;
    private final String _enrollingTokenType;
    private final List<Integer> pushtokenPollingInterval = new ArrayList<>();

    Configuration(Map<String, String> configMap) {
        _serverURL = configMap.get(Const.CONFIG_SERVER);
        _realm = configMap.get(Const.CONFIG_REALM) == null ? "" : configMap.get(Const.CONFIG_REALM);
        _doSSLVerify = configMap.get(Const.CONFIG_VERIFYSSL) != null && configMap.get(Const.CONFIG_VERIFYSSL).equals(Const.TRUE);
        _doTriggerChallenge = configMap.get(Const.CONFIG_DOTRIGGERCHALLENGE) != null && configMap.get(Const.CONFIG_DOTRIGGERCHALLENGE).equals(Const.TRUE);
        _serviceAccountName = configMap.get(Const.CONFIG_SERVICEACCOUNT) == null ? "" : configMap.get(Const.CONFIG_SERVICEACCOUNT);
        _serviceAccountPass = (configMap.get(Const.CONFIG_SERVICEPASS) == null) ? "" : configMap.get(Const.CONFIG_SERVICEPASS);
        _doEnrollToken = configMap.get(Const.CONFIG_ENROLLTOKEN) != null && configMap.get(Const.CONFIG_ENROLLTOKEN).equals(Const.TRUE);
        _enrollingTokenType = configMap.get(Const.CONFIG_ENROLLTOKENTYPE) == null ? "" : configMap.get(Const.CONFIG_ENROLLTOKENTYPE);

        String excludedGroupsStr = configMap.get(Const.CONFIG_EXCLUDEGROUPS);
        if (excludedGroupsStr != null) {
            _excludedGroups.addAll(Arrays.asList(excludedGroupsStr.split(",")));
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
        return _serverURL;
    }

    String getRealm() {
        return _realm;
    }

    boolean doSSLVerify() {
        return _doSSLVerify;
    }

    boolean doTriggerChallenge() {
        return _doTriggerChallenge;
    }

    String getServiceAccountName() {
        return _serviceAccountName;
    }

    String getServiceAccountPass() {
        return _serviceAccountPass;
    }

    List<String> getExcludedGroups() {
        return _excludedGroups;
    }

    boolean doEnrollToken() {
        return _doEnrollToken;
    }

    String getEnrollingTokenType() {
        return _enrollingTokenType;
    }

    List<Integer> getPushtokenPollingInterval() {
        return pushtokenPollingInterval;
    }
}
