function eventListeners()
{
    // AUTO SUBMIT
    if (piGetValue("autoSubmit"))
    {
        piSubmit();
    }

    // AUTO SUBMIT BY OTP LENGTH
    if (piGetValue("activateAutoSubmitOtpLength") === "1")
    {
        document.getElementById("otp").addEventListener("keyup", function ()
        {
            if (piGetValue('otp').length === parseInt(piGetValue("otpLength")))
            {
                piSubmit();
            }
        });
    }

    // BUTTON LISTENERS
    document.getElementById("webAuthnButton").addEventListener("click", function ()
    {
        piChangeMode("webauthn");
    });
    document.getElementById("pushButton").addEventListener("click", function ()
    {
        piChangeMode("push");
    });
    document.getElementById("otpButton").addEventListener("click", function ()
    {
        piChangeMode("otp");
    });

    // POLL BY RELOAD
    if (piGetValue("mode") === "push")
    {
        const pollingIntervals = [4, 3, 2];
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

        window.setTimeout(function ()
        {
            piSubmit();
        }, refreshTime);
    }

    // POLL IN BROWSER
    if (piGetValue("pollInBrowser") === "1"
        && piGetValue("pollInBrowserUrl").length > 0
        && piGetValue("transactionID").length > 0)
    {
        piDisableElement("pushButton");
        let worker;
        if (typeof (Worker) !== "undefined")
        {
            if (typeof (worker) == "undefined")
            {
                worker = new Worker("pi-pollTransaction.worker.js"); //todo check path
                document.getElementById("kc-login").addEventListener('click', function (e)
                {
                    worker.terminate();
                    worker = undefined;
                });
                worker.postMessage({'cmd': 'url', 'msg': piGetValue("pollInBrowserUrl")});
                worker.postMessage({'cmd': 'transactionID', 'msg': piGetValue("transactionID")});
                worker.postMessage({'cmd': 'start'});
                worker.addEventListener('message', function (e)
                {
                    let data = e.data;
                    switch (data.status)
                    {
                        case 'success':
                            piSubmit();
                            break;
                        case 'error':
                            console.log("Poll in browser error: " + data.message);
                            piSetValue("errorMessage", "Poll in browser error: " + data.message);
                            piSetValue("pollInBrowserFailed", true);
                            piEnableElement("pushButton");
                            worker = undefined;
                    }
                });
            }
        }
        else
        {
            console.log("Sorry! No Web Worker support.");
            worker.terminate();
            piSetValue("errorMessage", "Poll in browser error: The browser doesn't support the Web Worker.");
            piSetValue("pollInBrowserFailed", true);
            piEnableElement("pushButton");
        }
    }

    // ALTERNATE LANGUAGE
    if (piGetValue("uilanguage") === "de") {
        document.getElementById("alternateTokenHeader").innerText = "Alternative Anmeldeoptionen";
        piSetValue("kc-login", "Anmelden");
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    eventListeners();
});