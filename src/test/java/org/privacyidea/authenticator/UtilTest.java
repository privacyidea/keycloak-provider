/*
 * Copyright 2026 NetKnights GmbH - nils.behlen@netknights.it
 * - Modified
 * <p>
 * SPDX-License-Identifier: Apache-2.0
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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.privacyidea.AuthenticationStatus;
import org.privacyidea.Challenge;
import org.privacyidea.IPILogger;
import org.privacyidea.PIResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link Util} — the seam where the provider decides the client {@link Mode} and which
 * {@code NOTE_*_TRANSACTION_ID} auth note to store for a privacyIDEA challenge. This is the layer where the
 * push_code_to_phone bug surfaced (an interactive-mode challenge being submitted without its transaction id), so
 * the routing logic is worth pinning. The Keycloak surface is mocked to just the auth session and the user/group
 * lookups these methods actually touch.
 */
public class UtilTest
{
    private Util util;
    private Configuration config;

    @Before
    public void setup()
    {
        util = new Util(new NoopLogger());
        config = new Configuration(new HashMap<>());
    }

    // --- checkMFAExcludedByGroup ---

    @Test
    public void testNullUserRequiresMFA()
    {
        assertFalse(util.checkMFAExcludedByGroup(config, null));
    }

    @Test
    public void testExcludedGroupMemberSkipsMFA()
    {
        Map<String, String> map = new HashMap<>();
        map.put(Const.CONFIG_EXCLUDED_GROUPS, "no-mfa,other");
        Configuration cfg = new Configuration(map);

        assertTrue(util.checkMFAExcludedByGroup(cfg, userInGroups("no-mfa")));
        assertFalse(util.checkMFAExcludedByGroup(cfg, userInGroups("staff")));
    }

    @Test
    public void testIncludedGroupHasPrecedenceAndGatesMFA()
    {
        Map<String, String> map = new HashMap<>();
        // Included groups have precedence: only members of an included group do MFA; everyone else is excluded.
        map.put(Const.CONFIG_INCLUDED_GROUPS, "mfa-users");
        map.put(Const.CONFIG_EXCLUDED_GROUPS, "mfa-users");
        Configuration cfg = new Configuration(map);

        // Member of the included group -> MFA required -> not excluded
        assertFalse(util.checkMFAExcludedByGroup(cfg, userInGroups("mfa-users")));
        // Not a member of any included group -> excluded from MFA
        assertTrue(util.checkMFAExcludedByGroup(cfg, userInGroups("staff")));
    }

    // --- evaluateResponse: Mode + transaction-id routing ---

    @Test
    public void testPollPushChallengeRoutesToPushMode()
    {
        Capture capture = new Capture();
        AuthenticationFlowContext context = contextWithSession(capture.session);

        PIResponse response = challengeResponse("push", "poll", "PIPU001", "tx-push-1");
        AuthenticationForm form = util.evaluateResponse(response, context, new AuthenticationForm(config), config);

        assertEquals(Mode.PUSH, form.getMode());
        assertTrue(form.isPushAvailable());
        assertEquals("tx-push-1", capture.notes.get(Const.NOTE_PUSH_TRANSACTION_ID));
        assertNull(capture.notes.get(Const.NOTE_OTP_TRANSACTION_ID));
    }

    @Test
    public void testInteractiveOtpChallengeRoutesToOtpMode()
    {
        Capture capture = new Capture();
        AuthenticationFlowContext context = contextWithSession(capture.session);

        PIResponse response = challengeResponse("hotp", "interactive", "HOTP1", "tx-otp-1");
        AuthenticationForm form = util.evaluateResponse(response, context, new AuthenticationForm(config), config);

        assertEquals(Mode.OTP, form.getMode());
        assertEquals("tx-otp-1", capture.notes.get(Const.NOTE_OTP_TRANSACTION_ID));
        assertNull(capture.notes.get(Const.NOTE_PUSH_TRANSACTION_ID));
    }

    /**
     * push_code_to_phone: a push token delivered in interactive mode (client_mode=interactive). The user types the
     * code shown on the phone, so the challenge must be routed like an OTP — Mode.OTP and the transaction stored under
     * NOTE_OTP_TRANSACTION_ID, so the code is finalized against that transaction. Regression guard for the bug where
     * the code was submitted without a transaction id and rejected as "wrong otp pin". Requires java-client >= 1.6.0,
     * whose otpTransactionId() returns the id for interactive push.
     */
    @Test
    public void testCodeToPhoneChallengeRoutesToOtpModeWithTransaction()
    {
        Capture capture = new Capture();
        AuthenticationFlowContext context = contextWithSession(capture.session);

        // client_mode=interactive translates to preferredClientMode "otp" on the client side
        PIResponse response = challengeResponse("push", "interactive", "PIPU001", "tx-code-to-phone");
        AuthenticationForm form = util.evaluateResponse(response, context, new AuthenticationForm(config), config);

        assertEquals(Mode.OTP, form.getMode());
        assertEquals("tx-code-to-phone", capture.notes.get(Const.NOTE_OTP_TRANSACTION_ID));
    }

    // --- helpers ---

    /**
     * Build a CHALLENGE PIResponse with a single challenge. {@code preferredClientMode} uses the provider-side
     * (already-translated) mode names the wire parser produces: "poll" -> "push", "interactive" -> "otp".
     */
    private static PIResponse challengeResponse(String type, String clientMode, String serial, String transactionId)
    {
        PIResponse response = new PIResponse();
        response.authentication = AuthenticationStatus.CHALLENGE;
        response.status = true;
        response.value = false;
        response.type = type;
        response.serial = serial;
        response.transactionID = transactionId;
        response.preferredClientMode = "poll".equals(clientMode) ? "push" : "otp";
        response.multiChallenge.add(new Challenge(serial, "message", clientMode, "", transactionId, type));
        return response;
    }

    private static UserModel userInGroups(String... groupNames)
    {
        UserModel user = mock(UserModel.class);
        when(user.getGroupsStream()).thenAnswer(invocation -> Stream.of(groupNames).map(name ->
        {
            GroupModel group = mock(GroupModel.class);
            when(group.getName()).thenReturn(name);
            return group;
        }));
        return user;
    }

    private static AuthenticationFlowContext contextWithSession(AuthenticationSessionModel session)
    {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        when(context.getAuthenticationSession()).thenReturn(session);
        return context;
    }

    /** Records every setAuthNote(key, value) call into a map for assertions. */
    private static final class Capture
    {
        final AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        final Map<String, String> notes = new HashMap<>();

        Capture()
        {
            // Record every setAuthNote(key, value) call into the map for assertions
            org.mockito.Mockito.doAnswer(inv ->
            {
                notes.put(inv.getArgument(0), inv.getArgument(1));
                return null;
            }).when(session).setAuthNote(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
        }
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
