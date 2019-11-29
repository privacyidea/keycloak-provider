package org.privacyidea.authenticator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.privacyidea.authenticator.Const.*;

class Configuration {

    private String _serverURL;
    private String _realm;
    private boolean _doSSLVerify;
    private boolean _doTriggerChallenge;
    private String _serviceAccountName;
    private String _serviceAccountPass;
    private List<String> _excludedGroups = new ArrayList<>();
    private String _excludedHeader;
    private boolean _doEnrollToken;
    private String _enrollingTokenType;
    private List<Integer> _pushtokenPollingInterval = new ArrayList<>();

    Configuration(Map<String, String> configMap) {
        _serverURL = configMap.get(CONFIG_SERVER);
        _realm = configMap.get(CONFIG_REALM) == null ? "" : configMap.get(CONFIG_REALM);
        _doSSLVerify = configMap.get(CONFIG_VERIFYSSL) != null && configMap.get(CONFIG_VERIFYSSL).equals(TRUE);
        _doTriggerChallenge = configMap.get(CONFIG_DOTRIGGERCHALLENGE) != null && configMap.get(CONFIG_DOTRIGGERCHALLENGE).equals(TRUE);
        _serviceAccountName = configMap.get(CONFIG_SERVICEACCOUNT) == null ? "" : configMap.get(CONFIG_SERVICEACCOUNT);
        _serviceAccountPass = (configMap.get(CONFIG_SERVICEPASS) == null) ? "" : configMap.get(CONFIG_SERVICEPASS);
        _doEnrollToken = configMap.get(CONFIG_ENROLLTOKEN) != null && configMap.get(CONFIG_ENROLLTOKEN).equals(TRUE);
        _enrollingTokenType = configMap.get(CONFIG_ENROLLTOKENTYPE) == null ? "" : configMap.get(CONFIG_ENROLLTOKENTYPE);
        _excludedHeader = configMap.get(CONFIG_EXCLUDEHEADER) == null ? "" : configMap.get(CONFIG_EXCLUDEHEADER);

        String excludedGroupsStr = configMap.get(CONFIG_EXCLUDEGROUPS);
        if (excludedGroupsStr != null) {
            _excludedGroups.addAll(Arrays.asList(excludedGroupsStr.split(",")));
        }

        // Set default, overwrite if configured
        _pushtokenPollingInterval.addAll(DEFAULT_POLLING_ARRAY);
        String s = configMap.get(CONFIG_PUSHTOKENINTERVAL);
        if (s != null) {
            List<String> strPollingIntervals = Arrays.asList(s.split(","));
            if (!strPollingIntervals.isEmpty()) {
                _pushtokenPollingInterval.clear();
                for (String str : strPollingIntervals) {
                    try {
                        _pushtokenPollingInterval.add(Integer.parseInt(str));
                    } catch (NumberFormatException e) {
                        _pushtokenPollingInterval.add(DEFAULT_POLLING_INTERVAL);
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

    String getExcludedHeader() {
        return _excludedHeader;
    }

    boolean doEnrollToken() {
        return _doEnrollToken;
    }

    String getEnrollingTokenType() {
        return _enrollingTokenType;
    }

    List<Integer> getPushtokenPollingInterval() {
        return _pushtokenPollingInterval;
    }
}
