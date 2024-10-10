<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "header">
        ${msg("loginTitleHtml",realm.name)}
        
    <#elseif section = "form">
        <form id="kc-otp-login-form" onsubmit="login.disabled = true; return true;" class="${properties.kcFormClass!}"
              action="${url.loginAction}"
              method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcInputWrapperClass!}">
                    <#if (!hasError)!true>
                        <#if mode = "push">
                            <#if (pushImage!"") != "">
                                <div class="center-text">
                                    <img alt="chal_img" src="${pushImage}">
                                </div>
                            </#if>
                            <h4 class="bold-text">${pushMessage}</h4>
                        <#elseif mode = "webauthn">
                            <#if (webauthnImage!"") != "">
                                <div class="center-text">
                                    <img alt="chal_img" src="${webauthnImage}">
                                </div>
                            </#if>
                        <#elseif mode = "otp">
                            <#if (otpImage!"") != "">
                                <div class="center-text">
                                    <img alt="chal_img" src="${otpImage}">
                                </div>
                            </#if>
                            <h4 class="bold-text">${otpMessage}</h4>
                        <#else>
                            <h4 class="bold-text">${otpMessage}</h4>
                        </#if>
                    </#if>
                    <#-- Show QR code for new token, if one has been enrolled -->
                    <#if (tokenEnrollmentQR!"") != "">
                        <div class="center-text">
                            <img alt="qr_code" width="256" height="256" src="${tokenEnrollmentQR}">
                        </div>
                        Please scan the QR-Code with an authenticator app like "privacyIDEA Authenticator" or "Google Authenticator"
                    </#if>
                    <script>
                        function autoSubmit(inputObject, lengthStr)
                        {
                            let lengthInt = parseInt(lengthStr);
                            if (lengthInt != null && inputObject.value.length === lengthInt)
                            {
                                document.forms["kc-otp-login-form"].submit();
                            }
                        }
                    </script>

                    <input id="otp" name="otp" type="hidden" class="${properties.kcInputClass!}" onKeyUp="autoSubmit(this, ${otpLength!""})" autofocus/>
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
                    <input id="pushImage" name="pushImage" value="${pushImage!""}" type="hidden">
                    <input id="otpImage" name="otpImage" value="${otpImage!""}" type="hidden">
                    <input id="webauthnImage" name="webauthnImage" value="${webauthnImage!""}" type="hidden">
                    <input id="otpLength" name="otpLength" value="${otpLength!""}" type="hidden">
                    <input id="modeChanged" name="modeChanged" value="false" type="hidden">
                    <input id="pollInBrowserFailed" name="pollInBrowserFailed" value="${pollInBrowserFailed?c}"
                           type="hidden">
                    <input id="errorMsg" name="errorMsg" value="" type="hidden">

                    <input id="webauthnsignrequest" name="webauthnsignrequest" value="${webauthnsignrequest!""}"
                           type="hidden">
                    <input id="webauthnsignresponse" name="webauthnsignresponse" value="" type="hidden">
                    <input id="origin" name="origin" value="" type="hidden">

                    <input class="pf-c-button pf-m-primary pf-m-block btn-lg" name="login" id="kc-login" type="submit"
                           value="Sign in"/>
                    <input id="uilanguage" name="uilanguage" value="${uilanguage!"en"}" type="hidden">

                    <#-- ALTERNATE LOGIN OPTIONS class="${properties.kcFormButtonsClass!}" -->
                    <div id="alternateToken" class="padding-top-20">
                        <h3 id="alternateTokenHeader">Alternate Login Options</h3>

                        <div class="${properties.kcFormButtonsWrapperClass!}">
                            <script>
                                'use strict';
                                // Helper functions
                                function disable(id) {
                                    const element = document.getElementById(id)
                                    if (element != null) {
                                        element.style.display = "none";
                                    } else {
                                        console.log(id + " is null!");
                                    }
                                }

                                function enable(id) {
                                    const element = document.getElementById(id);
                                    if (element != null) {
                                        element.style.display = "initial";
                                    } else {
                                        console.log(id + " is null!");
                                    }
                                }

                                function value(id) {
                                    const element = document.getElementById(id);
                                    if (element != null) {
                                        return element.value;
                                    } else {
                                        console.log(id + " is null!");
                                    }
                                    return "";
                                }

                                function set(id, value) {
                                    const element = document.getElementById(id);
                                    if (element != null) {
                                        element.value = value;
                                    } else {
                                        console.log(id + " is null!");
                                    }
                                }
                                // End helper functions

                                function changeMode(newMode) {
                                    // Submit the form to pass the change to the authenticator
                                    set("mode", newMode);
                                    set("modeChanged", "true");
                                    document.forms["kc-otp-login-form"].submit();
                                }

                                if (value("uilanguage") === "de") {
                                    document.getElementById("alternateTokenHeader").innerText = "Alternative Anmeldeoptionen";
                                    set("kc-login", "Anmelden");
                                }
                            </script>

                            <!-- Poll in browser section. If poll in browser is enabled in config,
                                 the following script will process it in the background. -->
                            <#if transactionID?? && !(transactionID = "") && !(piPollInBrowserUrl = "") && (pollInBrowserFailed = false)>
                                <script>
                                    function workerError(message) {
                                        console.log("Poll in browser error: " + message);
                                        set("errorMsg", ("Poll in browser error: " + message));
                                        set("pollInBrowserFailed", true);
                                        enable("pushButton");
                                    }

                                    window.onload = () => {
                                        disable("pushButton");
                                        let worker;
                                        if (typeof (Worker) !== "undefined") {
                                            if (typeof (worker) == "undefined") {
                                                worker = new Worker("${url.resourcesPath}/pi-pollTransaction.worker.js");
                                                document.getElementById("kc-otp-login-form").addEventListener('submit', function (e) {
                                                    worker.terminate();
                                                    worker = undefined;
                                                })
                                                worker.postMessage({'cmd': 'url', 'msg': '${piPollInBrowserUrl}'});
                                                worker.postMessage({'cmd': 'transactionID', 'msg': '${transactionID}'});
                                                worker.postMessage({'cmd': 'start'});
                                                worker.addEventListener('message', function (e) {
                                                    let data = e.data;
                                                    switch (data.status) {
                                                        case 'success':
                                                            document.forms["kc-otp-login-form"].submit();
                                                            break;
                                                        case 'error':
                                                            workerError(data.message);
                                                            worker = undefined;
                                                    }
                                                })
                                            }
                                        } else {
                                            worker.terminate();
                                            workerError("The browser does not support Web Worker.")
                                        }
                                    };
                                </script>
                            </#if>

                            <#if mode = "push">
                            <#-- Polling for push by reloading every X seconds -->
                                <script>
                                    disable("kc-login");
                                    window.onload = () => {
                                        window.setTimeout(() => {
                                            document.forms["kc-otp-login-form"].submit()
                                        }, parseInt(${pollingInterval}) * 1000);
                                    };
                                </script>
                            <#if otp_available>
                            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                   name="otpButton" id="otpButton"
                                   onClick="changeMode('otp')"
                                   type="button" value="One-Time-Password"/>
                            </#if>
                            <#else>
                            <#--If token type is not push, an input field and login button is needed-->
                                <script>
                                    enable("kc-login");
                                    document.getElementById("otp").type = "password";
                                    document.getElementById("otp").required = true;
                                </script>
                            <#if push_available>
                            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                   name="pushButton" id="pushButton"
                                   onClick="changeMode('push')"
                                   type="button" value="Push"/>
                            </#if>
                            </#if>

                            <#-- WEBAUTHN -->
                            <#if !(webauthnsignrequest = "")>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                       name="webauthnButton" id="webauthnButton"
                                       onclick="doWebAuthn()"
                                       type="button" value="WebAuthn"/>

                                <script type="text/javascript" src="${url.resourcesPath}/pi-webauthn.js"></script>
                                <script>
                                    'use strict';
                                    if (value("webauthnsignrequest") === "") {
                                        disable("useWebAuthnButton");
                                    }

                                    if (value("mode") === "webauthn") {
                                        window.onload = () => {
                                            doWebAuthn();
                                        }
                                    }

                                    if (!window.location.origin) {
                                        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
                                    }
                                    set("origin", window.origin);

                                    function doWebAuthn() {
                                        // If we are in push mode, reload the page because in push mode the page refreshes every x seconds which could interrupt webauthn
                                        // Afterward, webauthn is started directly
                                        if (value("mode") === "push") {
                                            changeMode("webauthn");
                                        }
                                        try {
                                            const requestStr = value("webauthnsignrequest");
                                            const requestjson = JSON.parse(requestStr);

                                            const webAuthnSignResponse = window.pi_webauthn.sign(requestjson);
                                            webAuthnSignResponse.then((webauthnresponse) => {
                                                set("webauthnsignresponse", JSON.stringify(webauthnresponse));
                                                document.forms["kc-otp-login-form"].submit();
                                            });
                                        } catch (err) {
                                            console.log("Error while trying WebAuthn: " + err);
                                        }
                                    }
                                </script>
                            </#if>

                            <!-- Check if the alternate token options section should be displayed -->
                            <#if (!push_available || !(piPollInBrowserUrl! == "") && pollInBrowserFailed == false) && (webauthnsignrequest == "")>
                                <script>
                                    document.getElementById("alternateToken").style.display = "none";
                                </script>
                            </#if>

                            <#if hasError!false>
                                <script>
                                    disable("alternateToken");
                                    disable("kc-login");
                                    disable("otp");
                                    set("otpMessage", "");
                                </script>
                            </#if>
                        </div>
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>