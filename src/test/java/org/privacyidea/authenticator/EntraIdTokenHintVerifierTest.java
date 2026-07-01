package org.privacyidea.authenticator;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.privacyidea.IPILogger;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the fail-closed guards of {@link EntraIdTokenHintVerifier}. The actual RS256 signature
 * verification requires Microsoft's live keys and is covered by integration testing against EntraID; here we
 * assert that verification rejects malformed/untrusted input before any signature check.
 */
public class EntraIdTokenHintVerifierTest
{
    private static final String ENTRA_ISSUER = "https://login.microsoftonline.com/25b72930-b1b1-41d4-a9e1-6a934252571b/v2.0";

    private EntraIdTokenHintVerifier verifier;

    @Before
    public void setup()
    {
        verifier = new EntraIdTokenHintVerifier(new Util(new NoopLogger()));
    }

    @Test
    public void testRejectsTokenWithoutKid() throws Exception
    {
        // A syntactically valid JWT whose header has no 'kid' must be rejected before any key lookup.
        String jwt = jwt("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", "{\"iss\":\"" + ENTRA_ISSUER + "\"}");
        KeycloakSession session = mock(KeycloakSession.class);

        assertRejected(() -> verifier.verify(session, jwt, ENTRA_ISSUER, ""), "kid");
    }

    @Test
    public void testRejectsWhenJwksUriIsNotMicrosoft() throws Exception
    {
        // The discovery document points jwks_uri at a non-Microsoft host: keys must not be loaded from there.
        String jwt = jwt("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"abc\"}", "{\"iss\":\"" + ENTRA_ISSUER + "\"}");
        KeycloakSession session = mock(KeycloakSession.class);
        HttpClientProvider http = mock(HttpClientProvider.class);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(http);
        when(http.getString(ENTRA_ISSUER + "/.well-known/openid-configuration"))
                .thenReturn("{\"jwks_uri\":\"https://evil.example/keys\"}");

        assertRejected(() -> verifier.verify(session, jwt, ENTRA_ISSUER, ""), "non-EntraID jwks_uri");
    }

    @Test
    public void testRejectsWhenDiscoveryHasNoJwksUri() throws Exception
    {
        String jwt = jwt("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"abc\"}", "{\"iss\":\"" + ENTRA_ISSUER + "\"}");
        KeycloakSession session = mock(KeycloakSession.class);
        HttpClientProvider http = mock(HttpClientProvider.class);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(http);
        when(http.getString(ENTRA_ISSUER + "/.well-known/openid-configuration")).thenReturn("{}");

        assertRejected(() -> verifier.verify(session, jwt, ENTRA_ISSUER, ""), "jwks_uri");
    }

    private interface ThrowingRunnable
    {
        void run() throws Exception;
    }

    private static void assertRejected(ThrowingRunnable r, String expectedMessagePart)
    {
        try
        {
            r.run();
            fail("Expected VerificationException containing '" + expectedMessagePart + "'");
        }
        catch (VerificationException e)
        {
            assertTrue("Unexpected message: " + e.getMessage(), e.getMessage().contains(expectedMessagePart));
        }
        catch (Exception e)
        {
            fail("Expected VerificationException, got " + e);
        }
    }

    private static String jwt(String headerJson, String payloadJson)
    {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return enc.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
               + enc.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8)) + "."
               + enc.encodeToString("signature".getBytes(StandardCharsets.UTF_8));
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
