package org.privacyidea.authenticator;

import java.util.Arrays;
import java.util.List;

final class Const {
    private Const() {
    }

    static final String PROVIDER_ID = "privacyidea-authenticator";

    static final String GET = "GET";
    static final String POST = "POST";
    static final String TRUE = "true";

    static final String ENDPOINT_AUTH = "/auth";
    static final String ENDPOINT_TOKEN_INIT = "/token/init";
    static final String ENDPOINT_TRIGGERCHALLENGE = "/validate/triggerchallenge";
    static final String ENDPOINT_TOKEN_CHALLENGES = "/token/challenges";
    static final String ENDPOINT_VALIDATE_CHECK = "/validate/check";
    static final String ENDPOINT_TOKEN = "/token";

    static final String DEFAULT_PUSH_MESSAGE = "Please confirm the authentication on your mobile device";
    static final String DEFAULT_OTP_MESSAGE = "Please enter the OTP";

    static final int DEFAULT_POLLING_INTERVAL = 2; // Will be used if single value from config cannot be parsed
    static final List<Integer> DEFAULT_POLLING_ARRAY = Arrays.asList(5, 1, 1, 1, 2, 3); // Will be used if no intervals are specified

    static final String FORM_PUSHTOKEN_INTERVAL = "pushTokenInterval";
    static final String FORM_TOKEN_ENROLLMENT_QR = "tokenEnrollmentQR";
    static final String FORM_TOKENTYPE = "tokenType";
    static final String FORM_PUSHTOKEN = "pushToken";
    static final String FORM_OTPTOKEN = "otpToken";
    static final String FORM_PUSH_MESSAGE = "pushMessage";
    static final String FORM_OTP_MESSAGE = "otpMessage";
    static final String FORM_FILE_NAME = "privacyIDEA.ftl";
    static final String FORM_TOKENTYPE_CHANGED = "tokenTypeChanged";
    static final String FORM_PI_OTP = "pi_otp";

    static final String PARAM_KEY_USERNAME = "username";
    static final String PARAM_KEY_USER = "user";
    static final String PARAM_KEY_PASSWORD = "password";
    static final String PARAM_KEY_PASS = "pass";
    static final String PARAM_KEY_TYPE = "type";
    static final String PARAM_KEY_GENKEY = "genkey";
    static final String PARAM_KEY_TRANSACTION_ID = "transaction_id";
    static final String PARAM_KEY_REALM = "realm";

    static final String TOKEN_TYPE_PUSH = "push";
    static final String TOKEN_TYPE_OTP = "otp"; // Classic OTPs like HOTP/TOTP

    static final String AUTH_NOTE_TRANSACTION_ID = "pi.transaction_id";
    static final String AUTH_NOTE_AUTH_COUNTER = "authCounter";

    static final String JSON_KEY_DETAIL = "detail";
    static final String JSON_KEY_RESULT = "result";
    static final String JSON_KEY_VALUE = "value";
    static final String JSON_KEY_MESSAGE = "message";
    static final String JSON_KEY_MULTI_CHALLENGE = "multi_challenge";
    static final String JSON_KEY_TYPE = "type";
    static final String JSON_KEY_TOKEN = "token";
    static final String JSON_KEY_GOOGLEURL = "googleurl";
    static final String JSON_KEY_IMG = "img";
    static final String JSON_KEY_CHALLENGES = "challenges";
    static final String JSON_KEY_OTP_VALID = "otp_valid";
    static final String JSON_KEY_TRANSACTION_ID = "transaction_id";
    static final String JSON_KEY_MESSAGES = "messages";
    static final String JSON_KEY_TRANSACTION_IDS = "transaction_ids";
    static final String JSON_KEY_TOKENS = "tokens";
    static final String JSON_KEY_COUNT = "count";

    static final String CONFIG_PUSHTOKENINTERVAL = "pipushtokeninterval";
    static final String CONFIG_EXCLUDEGROUPS = "piexcludegroups";
    static final String CONFIG_ENROLLTOKENTYPE = "pienrolltokentype";
    static final String CONFIG_ENROLLTOKEN = "pienrolltoken";
    static final String CONFIG_SERVICEPASS = "piservicepass";
    static final String CONFIG_SERVICEACCOUNT = "piserviceaccount";
    static final String CONFIG_DOTRIGGERCHALLENGE = "pidotriggerchallenge";
    static final String CONFIG_VERIFYSSL = "piverifyssl";
    static final String CONFIG_REALM = "pirealm";
    static final String CONFIG_SERVER = "piserver";
}
