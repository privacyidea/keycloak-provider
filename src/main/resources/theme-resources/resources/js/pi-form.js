function doWebAuthn ()
{
    // If we are in push mode, reload the page because in push mode the page refreshes every x seconds which could interrupt WebAuthn
    // Afterward, WebAuthn is started directly
    if (piGetValue("mode") === "push")
    {
        piChangeMode("webauthn");
    }
    else
    {
        try
        {
            const requestStr = piGetValue("webauthnSignRequest");
            const requestJSON = JSON.parse(requestStr);
            const webAuthnSignResponse = window.pi_webauthn.sign(requestJSON);

            webAuthnSignResponse.then((webauthnResponse) => {
                piSetValue("webauthnSignResponse", JSON.stringify(webauthnResponse));
                piSubmit();
            });
        }
        catch (err)
        {
            console.log(piGetValue("webauthnErrorMsg") + err);
            piSetValue("errorMessage", piGetValue("webauthnErrorMsg") + err);
        }
    }
}

function piMain ()
{
    // ALTERNATE TOKEN SECTION VISIBILITY
    if (piGetValue("webauthnSignRequest").length < 1 && piGetValue("isPushAvailable") !== true)
    {
        piDisableElement("alternateToken");
    }

    // PUSH
    if (piGetValue("mode") === "push")
    {
        piDisableElement("kc-login");
        piDisableElement("otp");
        window.onload = () => {
            window.setTimeout(() => {
                piSubmit();
            }, parseInt(piGetValue("pollingInterval")) * 1000);
        }
    }

    // POLL BY RELOAD
    if (piGetValue("mode") === "push")
    {
        const pollingIntervals = [ 4, 3, 2 ];
        let loadCounter = piGetValue("loadCounter");
        let refreshTime;

        if (loadCounter > (pollingIntervals.length - 1))
        {
            refreshTime = pollingIntervals[(pollingIntervals.length - 1)];
        }
        else
        {
            refreshTime = pollingIntervals[Number(loadCounter - 1)];
        }

        refreshTime *= 1000;

        window.setTimeout(function () {
            piSubmit();
        }, refreshTime);
    }

    // WEBAUTHN
    if (piGetValue("mode") === "webauthn")
    {
        window.onload = () => {
            doWebAuthn();
        }
    }
    if (!window.location.origin)
    {
        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':'
                                 + window.location.port : '');
    }
    piSetValue("origin", window.origin);
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function () {
    piMain();
});