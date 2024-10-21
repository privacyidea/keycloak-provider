<#import "template.ftl" as layout>
<head>
    <link rel="stylesheet" href="${url.resourcesPath}/css/pi-form.css">
    <script type="text/javascript" src="${url.resourcesPath}/js/pi-webauthn.js"></script>
    <script type="text/javascript" src="${url.resourcesPath}/js/pi-utils.js"></script>
    <script type="text/javascript" src="${url.resourcesPath}/js/pi-eventListeners.js"></script>
    <script type="text/javascript" src="${url.resourcesPath}/js/pi-form.js"></script>
</head>
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
                    <input id="pushImage" name="pushImage" value="${pushImage!""}" type="hidden">
                    <input id="otpImage" name="otpImage" value="${otpImage!""}" type="hidden">
                    <input id="webauthnImage" name="webauthnImage" value="${webauthnImage!""}" type="hidden">
                    <input id="otpLength" name="otpLength" value="${otpLength!""}" type="hidden">
                    <input id="modeChanged" name="modeChanged" value="false" type="hidden">
                    <input id="resourcesPath" name="resourcesPath" value="${url.resourcesPath}" type="hidden">
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

                            <#if otp_available>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                       name="otpButton" id="otpButton" type="button" value="One-Time-Password"/>
                            </#if>

                            <#if push_available>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                       name="pushButton" id="pushButton"
                                       type="button" value="Push"/>
                            </#if>

                            <#-- WEBAUTHN -->
                            <#if !(webauthnsignrequest = "")>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
                                       name="webauthnButton" id="webAuthnButton"
                                       type="button" value="WebAuthn"/>
                            </#if>
                        </div>
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>