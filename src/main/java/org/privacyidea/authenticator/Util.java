package org.privacyidea.authenticator;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.Version;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;
import org.privacyidea.Challenge;
import org.privacyidea.IPILogger;
import org.privacyidea.PIResponse;
import org.privacyidea.PrivacyIDEA;

import static org.privacyidea.PIConstants.HEADER_USER_AGENT;
import static org.privacyidea.authenticator.Const.ENTRAID_ISSUER_HOSTS;
import static org.privacyidea.authenticator.Const.ENTRAID_USER_AGENT;
import static org.privacyidea.authenticator.Const.HEADER_ACCEPT_LANGUAGE;
import static org.privacyidea.authenticator.Const.NOTE_ENTRAID_FLOW;
import static org.privacyidea.authenticator.Const.TRUE;
import static org.privacyidea.authenticator.Const.NOTE_OTP_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_PASSKEY_REGISTRATION_SERIAL;
import static org.privacyidea.authenticator.Const.NOTE_PASSKEY_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_PREVIOUS_RESPONSE;
import static org.privacyidea.authenticator.Const.NOTE_PUSH_TRANSACTION_ID;
import static org.privacyidea.authenticator.Const.NOTE_WEBAUTHN_TRANSACTION_ID;

public class Util
{
    private final IPILogger logger;

    public Util(IPILogger logger)
    {
        this.logger = logger;
    }

    /**
     * Extract the headers that should be forwarded to privacyIDEA from the original request to keycloak. The header names
     * can be defined in the configuration of this provider. The accept-language header is included by default.
     * Also add the custom headers from the configuration if any are defined.
     *
     * @param context AuthenticationFlowContext
     * @param config  Configuration
     * @return Map of headers
     */
    Map<String, String> getHeaders(AuthenticationFlowContext context, Configuration config)
    {
        Map<String, String> headers = new LinkedHashMap<>();
        // Take all headers from config plus accept-language. Build a local list instead of mutating the
        // Configuration's list, which is shared (cached per realm) across concurrent logins.
        List<String> forwardedHeaders = new ArrayList<>(config.forwardedHeaders());
        forwardedHeaders.add(HEADER_ACCEPT_LANGUAGE);

        for (String header : forwardedHeaders.stream().distinct().toList())
        {
            List<String> headerValues = context.getSession().getContext().getRequestHeaders().getRequestHeaders().get(header);

            if (headerValues != null && !headerValues.isEmpty())
            {
                String temp = String.join(",", headerValues);
                headers.put(header, temp);
            }
            else
            {
                logger.log("No values for header " + header + " found.");
            }
        }
        headers.putAll(config.customHeaders());

        // The User-Agent identifies the plugin to privacyIDEA and is overridden only by the EntraID switch.
        // The forwarded-headers feature is meant for headers added by network hardware (proxies/load balancers),
        // not the client's real User-Agent, so a forwarded or custom User-Agent must never clobber the plugin's
        // identity: drop any incoming User-Agent first. With none present, the java-client sends its configured
        // default; for an EntraID flow we set the EntraID User-Agent, which then takes precedence (java-client >= 1.5.1).
        headers.keySet().removeIf(h -> h.equalsIgnoreCase(HEADER_USER_AGENT));
        String entraIdUserAgent = entraIdUserAgentIfApplicable(context, config);
        if (entraIdUserAgent != null)
        {
            headers.put(HEADER_USER_AGENT, entraIdUserAgent);
        }
        return headers;
    }

    /**
     * Build the User-Agent string for a request, e.g. "privacyIDEA-Keycloak/1.8.0 Keycloak/26.5.6".
     *
     * @param pluginName the leading product token (e.g. the plugin or the EntraID flow marker)
     * @return the User-Agent string
     */
    String buildUserAgent(String pluginName)
    {
        String providerVersion = PrivacyIDEAAuthenticator.class.getPackage().getImplementationVersion();
        return pluginName + "/" + providerVersion + " Keycloak/" + Version.VERSION;
    }

    /**
     * @return the EntraID User-Agent if the feature is enabled in the configuration and the current flow originates
     * from an EntraID (openid) request, otherwise null (in which case the client's configured default User-Agent is
     * used).
     */
    String entraIdUserAgentIfApplicable(AuthenticationFlowContext context, Configuration config)
    {
        if (config == null || !config.isEntraIdUserAgentEnabled())
        {
            return null;
        }
        AuthenticationSessionModel session = context.getAuthenticationSession();
        if (session != null && TRUE.equals(session.getAuthNote(NOTE_ENTRAID_FLOW)))
        {
            return buildUserAgent(ENTRAID_USER_AGENT);
        }
        return null;
    }

    /**
     * Checks whether the given id_token_hint issuer ("iss" claim) belongs to EntraID/Microsoft.
     * The issuer host must match one of the known Microsoft login hosts exactly (or be a subdomain of one),
     * so that a lookalike host such as "login.microsoftonline.com.evil.example" is not accepted.
     *
     * @param issuer the value of the "iss" claim, e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
     * @return true if the issuer originates from EntraID
     */
    boolean isEntraIDIssuer(String issuer)
    {
        if (StringUtil.isBlank(issuer))
        {
            return false;
        }
        try
        {
            String host = URI.create(issuer).getHost();
            if (host == null)
            {
                return false;
            }
            // Locale.ROOT to avoid the Turkish-I problem, and strip a trailing FQDN dot so that an
            // absolute host such as "login.microsoftonline.com." still matches.
            host = host.toLowerCase(Locale.ROOT);
            if (host.endsWith("."))
            {
                host = host.substring(0, host.length() - 1);
            }
            for (String entraHost : ENTRAID_ISSUER_HOSTS)
            {
                if (host.equals(entraHost) || host.endsWith("." + entraHost))
                {
                    return true;
                }
            }
        }
        catch (IllegalArgumentException e)
        {
            logger.error("Failed to parse openid issuer '" + issuer + "': " + e.getMessage());
        }
        return false;
    }

    /**
     * Check if the user is member of an included or excluded group. Included groups have precedence over excluded groups.
     * If user is null, return false (=MFA required).
     *
     * @param config Configuration
     * @param user   UserModel
     * @return true if no MFA is required, false if MFA is required
     */
    boolean checkMFAExcludedByGroup(Configuration config, UserModel user)
    {
        if (user == null || config == null)
        {
            return false;
        }
        if (!config.includedGroups().isEmpty())
        {
            Set<String> userGroups = collectGroupNames(user, config.isCheckInheritedGroups());
            return config.includedGroups().stream().noneMatch(userGroups::contains);
        }
        else if (!config.excludedGroups().isEmpty())
        {
            Set<String> userGroups = collectGroupNames(user, config.isCheckInheritedGroups());
            return config.excludedGroups().stream().anyMatch(userGroups::contains);
        }
        return false;
    }

    /**
     * Collect the names of all groups the user is a member of. If {@code includeInherited} is set, the parent groups
     * (ancestors) of each direct group are included by walking up the group hierarchy via {@link GroupModel#getParent()}.
     * <p>
     * NOTE: inherited matching only works when the hierarchy exists in Keycloak (native nested groups, or LDAP groups
     * imported with "Preserve Group Inheritance"). For flat-imported LDAP groups there are no parents to walk.
     *
     * @param user             the user
     * @param includeInherited whether to also include ancestor group names
     * @return set of group names
     */
    private Set<String> collectGroupNames(UserModel user, boolean includeInherited)
    {
        Set<String> names = new HashSet<>();
        user.getGroupsStream().forEach(group ->
        {
            // Guard against cycles (shouldn't happen in a Keycloak group tree, but be safe).
            Set<String> visited = new HashSet<>();
            GroupModel current = group;
            while (current != null && visited.add(current.getId()))
            {
                names.add(current.getName());
                current = includeInherited ? current.getParent() : null;
            }
        });
        return names;
    }

    private AuthenticationForm challengesToForm(AuthenticationForm authForm, PIResponse response, Configuration config,
                                                AuthenticationFlowContext context)
    {
        if (response == null || !response.hasChallenges())
        {
            return authForm;
        }
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        authForm.setChallengesTriggered(true);
        authForm.setEnrollViaMultichallengeOptional(response.isEnrollViaMultichallengeOptional);
        authForm.setEnrollViaMultichallenge(response.isEnrollViaMultichallenge);
        Mode mode = Mode.OTP;
        String newOtpMessage = response.otpMessage();

        // Images per challenge
        for (Challenge c : response.multiChallenge)
        {
            if ("poll".equals(c.getClientMode()))
            {
                if ("push".equals(c.getType()))
                {
                    String image = c.getImage();
                    if (StringUtil.isNotBlank(image))
                    {
                        authForm.setPushImage(image);
                        // TODO assume that if we have an image for a push token, it has to be enroll_via_multichallenge
                        mode = Mode.PUSH;
                        authForm.setOtpAvailable(false);
                    }
                }
                else if ("smartphone".equals(c.getType()))
                {
                    authForm.setSmartphoneImage(c.getImage());
                    mode = Mode.PUSH;
                    authenticationSession.setAuthNote(NOTE_PUSH_TRANSACTION_ID, c.getTransactionID());
                    authForm.setOtpAvailable(false);
                }
            }
            else if ("interactive".equals(c.getClientMode()))
            {
                authForm.setOtpImage(c.getImage());
            }
            else if ("webauthn".equals(c.getClientMode()))
            {
                authForm.setWebAuthnImage(c.getImage());
            }
        }

        // Poll in browser
        if (config.pollInBrowser() && response.pushAvailable())
        {
            authForm.setTransactionId(response.pushTransactionId());
            newOtpMessage = response.otpMessage() + ". " + response.pushMessage();
            String url = config.pollInBrowserUrl().isEmpty() ? config.serverURL() : config.pollInBrowserUrl();
            authForm.setPollInBrowserURL(url);
        }
        // Push
        if (response.pushAvailable())
        {
            authForm.setPushAvailable(true);
            authForm.setPushMessage(response.pushMessage());
        }
        // WebAuthn
        String signRequest = response.mergedSignRequest();
        if (signRequest != null && !signRequest.isEmpty())
        {
            authForm.setWebAuthnSignRequest(signRequest);
        }
        // Passkey Registration
        if (StringUtil.isNotBlank(response.passkeyRegistration))
        {
            authForm.setPasskeyRegistration(response.passkeyRegistration);
            authenticationSession.setAuthNote(NOTE_PASSKEY_REGISTRATION_SERIAL, response.serial);
            authenticationSession.setAuthNote(NOTE_PASSKEY_TRANSACTION_ID, response.transactionID);
        }

        // Passkey Authentication (possible with passkey_trigger_by_pin policy)
        if (StringUtil.isNotBlank(response.passkeyChallenge))
        {
            authForm.setPasskeyChallenge(response.passkeyChallenge);
            authenticationSession.setAuthNote(NOTE_PASSKEY_TRANSACTION_ID, response.transactionID);
            authForm.setMode(Mode.PASSKEY);
        }

        // Preferred client mode
        if (StringUtil.isNotBlank(response.preferredClientMode))
        {
            try
            {
                mode = Mode.valueOf(response.preferredClientMode.toUpperCase());
            }
            catch (IllegalArgumentException e)
            {
                logger.error("Preferred client mode " + response.preferredClientMode + " is not valid, defaulting to OTP.");
            }
        }
        // Using poll in browser does not require push mode
        if (mode.equals(Mode.PUSH) && config.pollInBrowser() && !authForm.isEnrollViaMultichallenge())
        {
            mode = Mode.OTP;
        }

        // Set the transactionIds for the different modes
        if (StringUtil.isNotBlank(response.otpTransactionId()))
        {
            authenticationSession.setAuthNote(NOTE_OTP_TRANSACTION_ID, response.otpTransactionId());
        }
        if (StringUtil.isNotBlank(response.pushTransactionId()))
        {
            authenticationSession.setAuthNote(NOTE_PUSH_TRANSACTION_ID, response.pushTransactionId());
        }
        if (StringUtil.isNotBlank(response.webAuthnTransactionId))
        {
            authenticationSession.setAuthNote(NOTE_WEBAUTHN_TRANSACTION_ID, response.webAuthnTransactionId);
        }
        authForm.setMode(mode);
        authForm.setOtpMessage(newOtpMessage);
        return authForm;
    }

    /**
     * Evaluate the response from privacyIDEA and set the form values accordingly. If there is a response, a new AuthenticationForm is created
     * and returned. Some values of the old form can be retained if they are not set to new values by the last response.
     * If there is no response, the old form is returned.
     *
     * @param response PIResponse
     * @param context  AuthenticationFlowContext
     * @param authForm AuthenticationForm from the previous step
     * @param config   Configuration
     * @return AuthenticationForm with new values or the old one if no response
     */
    AuthenticationForm evaluateResponse(PIResponse response, AuthenticationFlowContext context, AuthenticationForm authForm,
                                        Configuration config)
    {
        if (response != null)
        {
            Mode previousMode = authForm.getMode();
            authForm = new AuthenticationForm(config);
            authForm.setMode(previousMode);
            authForm.setEnrollmentLink(response.enrollmentLink);
            if (response.error != null)
            {
                authForm.setErrorMessage(response.error.message);
            }

            // New challenges
            // WebAuthn and Passkey are not in the multiChallenge array, they need separate conditions here!
            if (response.hasChallenges())
            {
                authForm = challengesToForm(authForm, response, config, context);
                // Set the current response as previous response.
                // Responses like "wrong otp" or "user not found" do not contain information that we need to remember.
                String p = response.toJSON();
                context.getAuthenticationSession().setAuthNote(NOTE_PREVIOUS_RESPONSE, p);
            }
            else if (!response.authenticationSuccessful())
            {
                // If the response is not successful, set the error message and restore the previous response to the authform
                String previousResponseString = context.getAuthenticationSession().getAuthNote(NOTE_PREVIOUS_RESPONSE);
                PIResponse previousResponse = PIResponse.fromJSON(previousResponseString);
                authForm = challengesToForm(authForm, previousResponse, config, context);
                authForm.setErrorMessage(response.message);
            }
        }
        return authForm;
    }

    Map<String, String> getAdditionalParamsFromContext(AuthenticationFlowContext context, Configuration config)
    {
        Map<String, String> additionalParams = new LinkedHashMap<>();
        if (config.forwardClientIP())
        {
            String clientIP = context.getConnection().getRemoteAddr();
            if (StringUtil.isBlank(clientIP))
            {
                logger.error("ClientIP is empty, cannot forward it to privacyIDEA.");
            }
            else
            {
                additionalParams.put("client", clientIP);
            }
        }
        return additionalParams;
    }

    PIResponse tryTriggerFirstStep(String username, PrivacyIDEA privacyIDEA, Configuration config, String currentPassword,
                                   Map<String, String> additionalParams, Map<String, String> headers)
    {
        // Try to trigger challenges if configured. Using a service account has precedence over sending the (static) password
        PIResponse triggerResponse = null;
        if (username != null)
        {
            if (config.triggerChallenge())
            {
                triggerResponse = privacyIDEA.triggerChallenges(username, additionalParams, headers);
            }
            else if (config.sendPassword())
            {
                if (currentPassword != null)
                {
                    triggerResponse = privacyIDEA.validateCheck(username, currentPassword, null, additionalParams, headers);
                }
                else
                {
                    logger.error("Cannot send password because it is null!");
                }
            }
            else if (config.sendStaticPass())
            {
                triggerResponse = privacyIDEA.validateCheck(username, config.staticPass(), null, additionalParams, headers);
            }
        }
        else
        {
            logger.error("Username is null, cannot trigger challenges.");
        }
        return triggerResponse;
    }

}