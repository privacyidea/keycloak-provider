<#import "template.ftl" as layout>
<!-- BASE JS SCRIPT: Create the formResult object (AuthenticationFormResult.java) -->
<script>
    //let data = "${authenticationForm}";
    //console.log(data.replace(/(&quot;)/g, "\""));
    let formResult = {
        passkeyLoginRequested: false
    };
</script>
<head>
    <link rel="stylesheet" href="${url.resourcesPath}/css/pi-form.css">
    <script type="text/javascript" src="${url.resourcesPath}/js/pi-webauthn.js"></script>
    <script type="text/javascript" src="${url.resourcesPath}/js/pi-form.js"></script>
</head>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "header">
        ${msg("loginTitleHtml",realm.name)}
    <#elseif section = "form">
        <form id="kc-otp-login-form" onsubmit="submitForm();"
              class="${properties.kcFormClass!}"
              action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcInputWrapperClass!}">
                    <!-- IMAGES AND PROMPTS -->
                    <!-- Show images if there is no error message, or if push has not been accepted yet -->
                    <#if !authenticationForm.errorMessage?has_content || authenticationForm.errorMessage == "push_auth_not_verified">
                        <#if authenticationForm.mode = "push" && !(authenticationForm.passkeyRegistration?has_content)>
                            <#if authenticationForm.pushImage?has_content>
                                <div class="center-text">
                                    <img alt="challenge_img" src="${authenticationForm.pushImage}">
                                </div>
                            </#if>
                            <#if authenticationForm.pushMessage?has_content>
                                <h4 class="bold-text">${authenticationForm.pushMessage}</h4>
                            </#if>
                        <#elseif authenticationForm.mode = "webauthn" && !(authenticationForm.passkeyRegistration?has_content)>
                            <#if authenticationForm.webAuthnImage?has_content>
                                <div class="center-text">
                                    <img alt="challenge_img" src="${authenticationForm.webAuthnImage}">
                                </div>
                            </#if>
                        <#elseif authenticationForm.mode = "otp" && !(authenticationForm.passkeyRegistration?has_content)>
                            <#if authenticationForm.otpImage?has_content>
                                <div class="center-text">
                                    <img alt="challenge_img" src="${authenticationForm.otpImage}">
                                </div>
                            </#if>
                        <#elseif authenticationForm.mode = "usernamepassword" && !(authenticationForm.passkeyRegistration?has_content)>
                            <h4 class="bold-text">${msg('privacyidea.usernamepasswordPrompt')}</h4>
                        <#elseif authenticationForm.mode = "username" && !(authenticationForm.passkeyRegistration?has_content)>
                            <h4 class="bold-text">${msg('privacyidea.usernamePrompt')}</h4>
                        <#elseif authenticationForm.mode = "password" && !(authenticationForm.passkeyRegistration?has_content)>
                            <h4 class="bold-text">${msg('privacyidea.passwordPrompt')}</h4>
                        </#if>
                        <!-- ENROLLMENT LINK & CANCEL ENROLLMENT -->
                        <#if authenticationForm.enrollmentLink?has_content>
                            <a href="${authenticationForm.enrollmentLink}"
                               target="_blank">${msg('privacyidea.enrollmentLinkText')}</a>
                        </#if>
                        <#if authenticationForm.enrollViaMultichallengeOptional>
                            <input class="pf-v5-c-button pf-m-block" id="cancelEnrollment"
                                   value="${msg('privacyidea.cancelEnrollment')}" name="cancelEnrollment"
                                   type="button" onclick="cancelEnrollment()"/>
                        </#if>
                    <#else>
                        <!-- ERROR MESSAGE -->
                        <div class="${properties.kcContentWrapperClass!}">
                            <div class="${properties.kcLabelWrapperClass!}">
                                <label for="login-error">
                                    <span class="${properties.kcLabelClass!}">
                                        <#if authenticationForm.errorMessage == "push_auth_not_verified">
                                            <p style="color:red;">${msg('privacyidea.pushNotYetVerified')}</p>
                                        <#elseif authenticationForm.errorMessage == "passkey_authentication_failed">
                                            <p style="color:red;">${msg('privacyidea.passkeyAuthenticationFailed')}</p>
                                        <#else>
                                            ${authenticationForm.errorMessage}
                                        </#if>
                                    </span>
                                </label>
                            </div>
                        </div>
                    </#if>
                    <!-- USERNAME INPUT -->
                    <#if ["usernamepassword", "username"]?seq_contains(authenticationForm.mode)
                    && !(authenticationForm.passkeyRegistration?has_content)>
                        <div class="${properties.kcContentWrapperClass!}">
                            <div class="${properties.kcLabelWrapperClass!}">
                                <label for="username"><span class="${properties.kcLabelClass!}">Username</span></label>
                            </div>
                            <div class="${properties.kcInputWrapperClass!}">
                                <input id="username" name="username" type="text" class="${properties.kcInputClass!}"
                                       value="" autofocus/>
                            </div>
                        </div>
                    </#if>
                    <!-- PASSWORD INPUT -->
                    <#if ["usernamepassword", "password"]?seq_contains(authenticationForm.mode)
                    && !(authenticationForm.passkeyRegistration?has_content)>
                        <div class="${properties.kcContentWrapperClass!}">
                            <div class="${properties.kcLabelWrapperClass!}">
                                <label for="password"><span class="${properties.kcLabelClass!}">Password</span></label>
                            </div>
                            <div class="${properties.kcInputWrapperClass!}">
                                <input id="password" name="password" type="password" class="${properties.kcInputClass!}"
                                       value="" autofocus/>
                            </div>
                        </div>
                    </#if>
                    <!-- OTP INPUT -->
                    <#if !(["usernamepassword", "username", "push", "passkey"]?seq_contains(authenticationForm.mode))
                    &&  !(authenticationForm.passkeyRegistration?has_content)>
                        <div class="${properties.kcContentWrapperClass!}">
                            <div class="${properties.kcLabelWrapperClass!}">
                                <label for="otp"><span class="${properties.kcLabelClass!}">
                                        <#if (authenticationForm.otpMessage)?has_content>
                                            ${authenticationForm.otpMessage}
                                        <#else>
                                            ${msg('privacyidea.otpPrompt')}
                                        </#if>
                                    </span></label>
                            </div>
                            <div class="${properties.kcInputWrapperClass!}">
                                <input id="otp" name="otp" type="password" class="${properties.kcInputClass!}"
                                       value="" autocomplete="new-password" autofocus/>
                            </div>
                        </div>
                    </#if>
                    <!-- Passkey Registration (enroll_via_multichallenge) with retry button -->
                    <#if authenticationForm.passkeyRegistration?has_content>
                        <script>
                            registerPasskey("${authenticationForm.passkeyRegistration}");
                        </script>
                        <input class="pf-v5-c-button pf-m-primary pf-m-block" id="retryPasskeyRegistration"
                               value="${msg('privacyidea.passkeyRegisterRetryButton')}" name="retryPasskeyRegistration"
                               type="button" onclick="registerPasskey('${authenticationForm.passkeyRegistration}')"/>
                    </#if>
                </div>
            </div>

            <!-- Sign In Button -->
            <#if !(["passkey", "push"]?seq_contains(authenticationForm.mode)) && !(authenticationForm.passkeyRegistration?has_content)>
                <div id="kc-username" class="${properties.kcFormGroupClass!}">
                    <input class="pf-v5-c-button pf-m-primary pf-m-block" name="login" id="kc-login"
                           type="submit" value="${msg('privacyidea.signIn')}"/>
                </div>
            </#if>

            <!-- AuthenticationFormResult: JSON of that class with the data that has to be passed back -->
            <input id="authenticationFormResult" name="authenticationFormResult" value="" type="hidden">
            <!-- Readonly authenticationForm is also passed back to preserve the state -->
            <input id="authenticationForm" name="authenticationForm" value="${authenticationForm!""}" type="hidden">

            <!-- Passkey login feature toggle -->
            <#if !authenticationForm.disablePasskeyLogin>
                <!-- Passkey Button: Initiate passkey login by getting a challenge -->
            <#if !authenticationForm.passkeyRegistration?has_content && authenticationForm.firstStep>
                <div class="${properties.kcFormGroupClass!}">
                    <input class="pf-v5-c-button pf-m-block" type="button"
                           name="passkeyInitiateButton" id="passkeyInitiateButton" onclick="requestPasskeyLogin()"
                           value="${msg('privacyidea.passkeyInitiateButton')}"/>
                </div>
            </#if>
                <!-- Passkey Authentication with retry button -->
            <#if authenticationForm.passkeyChallenge?has_content && (!authenticationForm.errorMessage?has_content
            || authenticationForm.errorMessage == "passkey_authentication_failed")>

            <input class="pf-v5-c-button pf-m-primary pf-m-block" id="retryPasskeyAuthentication"
                   value="${msg('privacyidea.passkeyRetryButton')}" name="retryPasskeyAuthentication" type="button"
                   onclick="passkeyAuthentication('${authenticationForm.passkeyChallenge}', '${authenticationForm.mode}')"/>
            <input class="pf-v5-c-button pf-m-block" id="resetAuthentication"
                   value="${msg('privacyidea.resetLogin')}" name="resetAuthentication" type="button"
                   onclick="authenticationReset()"/>
            </#if>
                <!-- Only trigger passkey authentication automatically if there has been no error before -->
            <#if authenticationForm.passkeyChallenge?has_content && !authenticationForm.errorMessage?has_content>
                <script>
                    passkeyAuthentication("${authenticationForm.passkeyChallenge}", "${authenticationForm.mode}");
                </script>
            </#if>
            </#if> <!-- END OF PASSKEY -->

            <!-- AUTO SUBMIT -->
            <#if authenticationForm.autoSubmitLength?has_content>
                <script>
                    setAutoSubmit("${authenticationForm.autoSubmitLength}");
                </script>
            </#if>
            <!-- PUSH POLLING-->
            <#if authenticationForm.mode = "push">
                <script>
                    setPushReload(${authenticationForm.pollInterval});
                </script>
            </#if>
            <#if authenticationForm.pollInBrowserAvailable>
                <script>
                    startPollingInBrowser("${authenticationForm.pollInBrowserURL}", "${authenticationForm.transactionId}", "${url.resourcesPath}");
                </script>
            </#if>
            <!-- WEBAUTHN -->
            <#if authenticationForm.mode = "webauthn" && authenticationForm.webAuthnSignRequest?has_content>
                <script>
                    webAuthnAuthentication('${authenticationForm.webAuthnSignRequest}', '${authenticationForm.mode}');
                </script>
            </#if>

            <!-- OTHER LOGIN OPTIONS DIV -->
            <#if !authenticationForm.firstStep && !authenticationForm.passkeyChallenge?has_content
            && !authenticationForm.passkeyRegistration?has_content>
                <div id="alternateToken" class="${properties.kcFormButtonsClass!}">
                    <h3 id="alternateTokenHeader">${msg('privacyidea.alternateLoginOptions')}</h3>
                    <!-- Passkey Button: Initiate passkey login by getting a challenge -->
                    <#if !authenticationForm.disablePasskeyLogin && !authenticationForm.passkeyRegistration?has_content
                    && !authenticationForm.firstStep>
                        <div class="${properties.kcFormGroupClass!}">
                            <input class="pf-v5-c-button pf-m-block" type="button"
                                   name="passkeyInitiateButton" id="passkeyInitiateButton"
                                   onclick="requestPasskeyLogin()"
                                   value="${msg('privacyidea.passkeyInitiateButton')}"/>
                        </div>
                    </#if>
                    <!-- OTP Button -->
                    <#if authenticationForm.otpAvailable && authenticationForm.mode != "otp">
                        <input class="pf-v5-c-button pf-m-block" id="otpButton"
                               name="otpButton" onclick="changeMode('otp')"
                               type="button" value="${msg('privacyidea.otpButton')}"/>
                    </#if>
                    <!-- Push Button -->
                    <#if authenticationForm.pushAvailable && authenticationForm.mode != "push">
                        <input class="pf-v5-c-button pf-m-block" id="pushButton"
                               name="pushButton" onclick="changeMode('push')"
                               type="button" value="${msg('privacyidea.pushButton')}"/>
                    </#if>
                    <!-- WebAuthn Button -->
                    <#if authenticationForm.webAuthnSignRequest?has_content>
                        <input class="pf-v5-c-button pf-m-block" id="webAuthnButton"
                               onclick="webAuthnAuthentication('${authenticationForm.webAuthnSignRequest}', '${authenticationForm.mode}')"
                               name="webauthnButton" type="button"
                               value="${msg('privacyidea.webauthnButton')}"/>
                    </#if>
                </div>
            </#if>
            <script>
                // If none of the buttons of the "other login options" are shown, hide the whole div with the text
                // This is easier than having a huge check for the div, as each button can have its own logic
                setLoginOptionsVisibility();
            </script>
        </form>
    </#if>
</@layout.registrationLayout>