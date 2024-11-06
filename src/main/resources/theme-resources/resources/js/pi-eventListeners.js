function eventListeners()
{
    // AUTO SUBMIT BY OTP LENGTH
    if (piGetValue("otpLength").length > 0)
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

    // POLL IN BROWSER
    if (piGetValue("pollInBrowserUrl").length > 0
        && piGetValue("transactionID").length > 0)
    {
        piDisableElement("pushButton");
        let worker;
        if (typeof (Worker) !== "undefined")
        {
            if (typeof (worker) == "undefined")
            {
                worker = new Worker(piGetValue("resourcesPath") + "/js/pi-pollTransaction.worker.js");
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
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function ()
{
    eventListeners();
});