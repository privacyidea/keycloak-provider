<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "header">
        ${msg("loginTitleHtml",realm.name)}
    <#elseif section = "form">
        <form id="loginform" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcInputWrapperClass!}">
                    <#if tokenType = "push">
                        ${pushMessage}
                    <#else>
                        ${otpMessage}
                    </#if>
                    <#-- Show QR code for new token, if one has been enrolled -->
                    <#if tokenEnrollmentQR != "">
                        <div style="text-align: center;">
                            <img width="256" height="256" src="${tokenEnrollmentQR}">
                        </div>
                        Please scan the QR-Code with an authenticator app like "privacyIDEA Authenticator" or "Google Authenticator"
                    </#if>
                    <input id="pi_otp" name="pi_otp" type="hidden" class="${properties.kcInputClass!}" autofocus/>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}"/>
                </div>

                <#--These inputs will be returned to privacyIDEAAuthenticator-->
                <input id="tokenEnrollmentQR" name="tokenEnrollmentQR" value="${tokenEnrollmentQR}" type="hidden">
                <input id="tokenType" name="tokenType" value="${tokenType}" type="hidden">
                <input id="pushToken" name="pushToken" value="${pushToken?c}" type="hidden">
                <input id="otpToken" name="otpToken" value="${otpToken?c}" type="hidden">
                <input id="pushMessage" name="pushMessage" value="${pushMessage}" type="hidden">
                <input id="otpMessage" name="otpMessage" value="${otpMessage}" type="hidden">
                <input id="tokenTypeChanged" name="tokenTypeChanged" value="false" type="hidden">

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                        <#if tokenType = "push">
                        <#--The form will be reloaded if push token is enabled to check if it is confirmed.
                        The interval can be set in the configuration-->
                            <script>
                                window.onload = function () {
                                    window.setTimeout(function () {
                                        document.forms["loginform"].submit();
                                    }, parseInt(${pushTokenInterval}) * 1000);
                                };
                            </script>
                        <#if otpToken>
                        <#--The token type can be changed if we can use push or otp-->
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                               name="changeTokenTypeButton" id="changeTokenTypeButton" onClick="changeTokenType('otp')"
                               type="button" value="Use OTP"/>
                        </#if>
                        <#else>
                        <#--If token type is not push, an input field and login button is needed-->
                            <script>
                                document.getElementById("pi_otp").type = "password";
                                document.getElementById("pi_otp").required = true;
                            </script>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                               name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                        <#if pushToken>
                        <#--The token type can be changed if we can use push or otp-->
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                               name="changeTokenTypeButton" id="changeTokenTypeButton" onClick="changeTokenType('push')"
                               type="button" value="Use Push Token"/>
                        </#if>
                        <#--If we change the token type, this information must be transmitted to privacyIDEAAuthenticator-->
                        <script>
                            function changeTokenType(tokenType) {
                                document.getElementById("tokenType").value = tokenType;
                                document.getElementById("tokenTypeChanged").value = "true";
                                document.forms["loginform"].submit();
                            }
                        </script>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                               name="cancel" id="kc-cancel" type="submit" value="${msg("doCancel")}"/>
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
