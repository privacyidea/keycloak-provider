<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "header">
        ${msg("loginTitleHtml",realm.name)}
    <#elseif section = "form">
        <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcInputWrapperClass!}">
                    <#if (!hasError)!true>
                        <#if mode = "push">
                          <h4 style="font-weight: bold">${pushMessage}</h4>
                        <#else>
                            <h4 style="font-weight: bold">${otpMessage}</h4>
                        </#if>
                    </#if>
                    <#-- Show QR code for new token, if one has been enrolled -->
                    <#if (tokenEnrollmentQR!"") != "">
                        <div style="text-align: center;">
                            <img width="256" height="256" src="${tokenEnrollmentQR}">
                        </div>
                        Please scan the QR-Code with an authenticator app like "privacyIDEA Authenticator" or "Google Authenticator"
                    </#if>
                    <input id="otp" name="otp" type="hidden" class="${properties.kcInputClass!}" autofocus/>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <#-- These inputs will be returned to privacyIDEAAuthenticator -->
                    <input id="mode" name="mode" value="${mode}" type="hidden">
                    <input id="push_available" name="push_available" value="${push_available?c}" type="hidden">
                    <input id="otp_available" name="otp_available" value="${otp_available?c}" type="hidden">
                    <input id="pushMessage" name="pushMessage" value="${pushMessage!""}" type="hidden">
                    <input id="otpMessage" name="otpMessage" value="${otpMessage!""}" type="hidden">
                    <input id="modeChanged" name="modeChanged" value="false" type="hidden">

                    <input id="webauthnsignrequest" name="webauthnsignrequest" value="${webauthnsignrequest!""}"
                           type="hidden">
                    <input id="webauthnsignresponse" name="webauthnsignresponse" value="" type="hidden">
                    <input id="origin" name="origin" value="" type="hidden">

                    <input id="u2fsignrequest" name="u2fsignrequest" value="${u2fsignrequest!""}"
                           type="hidden">
                    <input id="u2fsignresponse" name="u2fsignresponse" value="" type="hidden">

                    <input class="pf-c-button pf-m-primary pf-m-block btn-lg" name="login" id="kc-login" type="submit"
                           value="Sign in"/>
                    <input id="uilanguage" name="uilanguage" value="${uilanguage!"en"}" type="hidden">

                    <#-- ALTERNATE LOGIN OPTIONS class="${properties.kcFormButtonsClass!}" -->
                    <div id="alternateToken" style="padding-top: 20px">
                        <h3 id="alternateTokenHeader">Alternate Login Options</h3>

                        <div class="${properties.kcFormButtonsWrapperClass!}">
                            <script>
                                'use strict';

                                if (document.getElementById("uilanguage").value === "de") {
                                    document.getElementById("alternateTokenHeader").innerText = "Alternative Anmeldeoptionen";
                                    document.getElementById("kc-login").value = "Anmelden";
                                }

                                function changeMode(newMode) {
                                    // Submit the form to pass the change to the authenticator
                                    document.getElementById("mode").value = newMode;
                                    document.getElementById("modeChanged").value = "true";
                                    document.forms["kc-otp-login-form"].submit();
                                }
                            </script>

                            <#if mode = "push">
                            <#--The form will be reloaded if push token is enabled to check if it is confirmed.
                            The interval can be set in the configuration-->
                                <script>
                                    document.getElementById("kc-login").style.display = "none";
                                    window.onload = () => {
                                        window.setTimeout(() => {
                                            document.forms["kc-otp-login-form"].submit();
                                        }, parseInt(${pollingInterval}) * 1000);
                                    };
                                </script>
                            <#if otp_available>
                            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                   name="changeModeButton" id="changeModeButton"
                                   onClick="changeMode('otp')"
                                   type="button" value="One-Time-Password"/>
                            </#if>
                            <#else>
                            <#--If token type is not push, an input field and login button is needed-->
                                <script>
                                    document.getElementById("kc-login").style.display = "initial";
                                    document.getElementById("otp").type = "password";
                                    document.getElementById("otp").required = true;
                                </script>
                            <#if push_available>
                            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                   name="changeModeButton" id="changeModeButton"
                                   onClick="changeMode('push')"
                                   type="button" value="Push"/>
                            </#if>
                            </#if>

                            <#-- WEBAUTHN -->
                            <#if !(webauthnsignrequest = "")>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                       name="useWebAuthnButton" id="useWebAuthnButton"
                                       onclick="doWebAuthn()"
                                       type="button" value="WebAuthn"/>

                                <script type="text/javascript" src="${url.resourcesPath}/pi-webauthn.js"></script>
                                <script>
                                    'use strict';
                                    if (document.getElementById("webauthnsignrequest").value === "") {
                                        document.getElementById("useWebAuthnButton").style.display = "none";
                                    }

                                    if (document.getElementById("mode").value === "webauthn") {
                                        window.onload = () => {
                                            doWebAuthn();
                                        }
                                    }

                                    if (!window.location.origin) {
                                        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
                                    }
                                    document.getElementById("origin").value = window.origin;

                                    function doWebAuthn() {
                                        // If we are in push mode, reload the page because in push mode the page refreshes every x seconds which could interrupt webauthn
                                        // Afterward, webauthn is started directly
                                        if (document.getElementById("mode").value === "push") {
                                            changeMode("webauthn");
                                        }
                                        try {
                                            const requestStr = document.getElementById("webauthnsignrequest").value;
                                            const requestjson = JSON.parse(requestStr);

                                            const webAuthnSignResponse = window.pi_webauthn.sign(requestjson);
                                            webAuthnSignResponse.then((webauthnresponse) => {
                                                document.getElementById("webauthnsignresponse").value = JSON.stringify(webauthnresponse);
                                                document.forms["kc-otp-login-form"].submit();
                                            });
                                        } catch (err) {
                                            console.log("Error while trying WebAuthn: " + err);
                                            alert("Error while trying WebAuthn: " + err);
                                        }
                                    }
                                </script>
                            </#if>

                            <#-- U2F -->
                            <#if !(u2fsignrequest = "")>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                       name="useU2FButton" id="useU2FButton"
                                       onclick="doU2F()"
                                       type="button" value="U2F"/>

                                <script type="text/javascript" src="${url.resourcesPath}/pi-u2f.js"></script>

                                <script>
                                    'use strict';
                                    if (document.getElementById("u2fsignrequest").value === "") {
                                        document.getElementById("useU2FButton").style.display = "none";
                                    }

                                    if (document.getElementById("mode").value === "u2f") {
                                        window.onload = () => {
                                            doU2F();
                                        }
                                    }

                                    function doU2F() {
                                        // If we are in push mode, reload the page because in push mode the page refreshes every x seconds which could interrupt U2F
                                        // Afterward, U2F is started directly
                                        if (document.getElementById("mode").value === "push") {
                                            changeMode("u2f");
                                        }

                                        if (!window.isSecureContext) {
                                            alert("Unable to proceed with U2F because the context is insecure!");
                                            console.log("Insecure context detected: Aborting U2F authentication!")
                                            changeMode("otp");
                                            return;
                                        }

                                        const requestStr = document.getElementById("u2fsignrequest").value;

                                        if (requestStr === null) {
                                            alert("Could not load U2F library. Please try again or use other token.");
                                            changeMode("otp");
                                            return;
                                        }

                                        try {
                                            const requestjson = JSON.parse(requestStr);
                                            sign_u2f_request(requestjson);
                                        } catch (err) {
                                            console.log("Error while signing U2FSignRequest: " + err);
                                            alert("Error while signing U2FSignRequest: " + err);
                                        }
                                    }

                                    function sign_u2f_request(signRequest) {
                                        let appId = signRequest["appId"];
                                        let challenge = signRequest["challenge"];
                                        let registeredKeys = [];

                                        registeredKeys.push({
                                            version: "U2F_V2",
                                            keyHandle: signRequest["keyHandle"]
                                        });

                                        u2f.sign(appId, challenge, registeredKeys, function (result) {
                                            const stringResult = JSON.stringify(result);
                                            if (stringResult.includes("clientData") && stringResult.includes("signatureData")) {
                                                document.getElementById("u2fsignresponse").value = stringResult;
                                                changeMode("u2f");
                                                document.forms["kc-otp-login-form"].submit();
                                            } else {
                                                console.log("Malformed U2F signing result: " + stringResult);
                                            }
                                        })
                                    }
                                </script>
                            </#if>

                            <#if !push_available && (u2fsignrequest = "") && (webauthnsignrequest = "")>
                                <script>
                                    document.getElementById("alternateToken").style.display = "none";
                                </script>
                            </#if>

                            <#if hasError!false>
                                <script>
                                    document.getElementById("alternateToken").style.display = "none";
                                    document.getElementById("kc-login").style.display = "none";
                                    document.getElementById("otp").style.display = "none";
                                    document.getElementById("otpMessage").value = "";
                                </script>
                            </#if>
                        </div>
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>