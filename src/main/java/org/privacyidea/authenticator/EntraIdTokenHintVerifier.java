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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.util.function.Predicate;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JWKSUtils;
import org.keycloak.utils.StringUtil;

/**
 * Verifies the id_token_hint that Microsoft Entra ID sends to an external authentication method.
 * <p>
 * Microsoft recommends the provider fully validate the id_token_hint - in particular the signature, issuer and
 * audience - see
 * <a href="https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-external-method-provider">
 * External MFA Method Provider Reference</a>. The signing keys are Microsoft's, discovered from the issuer's OIDC
 * discovery document and cached by Keycloak's {@link PublicKeyStorageProvider}.
 * <p>
 * Note: the id_token_hint is intentionally issued in an expired state ("To prevent the token from being used for
 * anything other than a hint, it's issued in the expired state"), so expiration is NOT checked here.
 */
class EntraIdTokenHintVerifier
{
    private final Util util;
    private final Gson gson = new Gson();

    EntraIdTokenHintVerifier(Util util)
    {
        this.util = util;
    }

    /**
     * Verifies the signature, issuer and (if configured) audience of an EntraID id_token_hint.
     * Expiration is deliberately not checked, because Entra issues the hint already expired.
     *
     * @param session          the Keycloak session, used for HTTP and cached key storage
     * @param idTokenHint      the raw JWT passed as id_token_hint
     * @param issuer           the value of the token's "iss" claim, already confirmed to be an EntraID issuer
     * @param expectedAudience the expected "aud" (the client ID Entra was given); if blank, the aud check is skipped
     * @throws VerificationException if the token cannot be verified
     */
    void verify(KeycloakSession session, String idTokenHint, String issuer, String expectedAudience) throws VerificationException
    {
        final String kid;
        try
        {
            kid = new JWSInput(idTokenHint).getHeader().getKeyId();
        }
        catch (Exception e)
        {
            throw new VerificationException("Failed to parse id_token_hint header: " + e.getMessage(), e);
        }
        if (StringUtil.isBlank(kid))
        {
            throw new VerificationException("id_token_hint has no 'kid' in its header");
        }

        String jwksUri = resolveJwksUri(session, issuer);
        // Defense in depth: the keys must be served from a Microsoft host as well, not just the issuer.
        if (!util.isEntraIDIssuer(jwksUri))
        {
            throw new VerificationException("Refusing to load keys from non-EntraID jwks_uri '" + jwksUri + "'");
        }

        PublicKeyLoader loader = () -> JWKSUtils.getKeyWrappersForUse(JWKSHttpUtils.sendJwksRequest(session, jwksUri), JWK.Use.SIG);
        PublicKeyStorageProvider keyStorage = session.getProvider(PublicKeyStorageProvider.class);
        // Match by kid only (Microsoft's JWKS often omits per-key 'alg', which would break kid+alg matching).
        // Cache the keys under the issuer. If the kid is unknown (e.g. after a key rollover), force a reload once.
        Predicate<KeyWrapper> byKid = k -> kid.equals(k.getKid());
        KeyWrapper key = keyStorage.getFirstPublicKey(issuer, byKid, loader);
        if (key == null)
        {
            keyStorage.reloadKeys(issuer, loader);
            key = keyStorage.getFirstPublicKey(issuer, byKid, loader);
        }
        if (key == null)
        {
            throw new VerificationException("No matching signing key (kid '" + kid + "') found for issuer '" + issuer + "'");
        }

        TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(idTokenHint, JsonWebToken.class)
                                                            .verifierContext(new AsymmetricSignatureVerifierContext(key))
                                                            .checkActive(false)   // Entra issues the hint already expired.
                                                            .checkTokenType(false) // the hint is not a bearer/access token.
                                                            .checkRealmUrl(false); // the issuer is validated explicitly below.
        if (StringUtil.isNotBlank(expectedAudience))
        {
            verifier.audience(expectedAudience);
        }
        verifier.verify();

        // The 'iss' claim is compared explicitly: the signature only proves Microsoft signed *some* token, so the
        // issuer in the payload must match the issuer whose keys we used.
        String tokenIssuer = verifier.getToken().getIssuer();
        if (tokenIssuer == null || !tokenIssuer.equals(issuer))
        {
            throw new VerificationException("id_token_hint issuer '" + tokenIssuer + "' does not match expected '" + issuer + "'");
        }
    }

    /**
     * Fetches the issuer's OIDC discovery document and returns its jwks_uri.
     */
    private String resolveJwksUri(KeycloakSession session, String issuer) throws VerificationException
    {
        String discoveryUrl = (issuer.endsWith("/") ? issuer : issuer + "/") + ".well-known/openid-configuration";
        try
        {
            String json = session.getProvider(HttpClientProvider.class).getString(discoveryUrl);
            JsonObject config = gson.fromJson(json, JsonObject.class);
            String jwksUri = (config != null && config.has("jwks_uri")) ? config.get("jwks_uri").getAsString() : null;
            if (StringUtil.isBlank(jwksUri))
            {
                throw new VerificationException("Discovery document at '" + discoveryUrl + "' has no jwks_uri");
            }
            return jwksUri;
        }
        catch (VerificationException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new VerificationException("Failed to fetch OIDC discovery document from '" + discoveryUrl + "': " + e.getMessage(), e);
        }
    }
}
