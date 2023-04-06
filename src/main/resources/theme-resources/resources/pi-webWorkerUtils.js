let w;

function startPollWorker()
{
    if (typeof (Worker) !== "undefined")
    {
        if (typeof (w) == "undefined")
        {
            w = new Worker(sessionStorage.getItem("piResourcesPath") + "/pi-pollTransaction.js");
            console.log("Setting new Worker..."); //todo rm
        }
        w.onmessage = function (event)
        {
            if (event.data === true)
            {
                console.log("privacyIDEA: Poll transaction result succeeded!");
                document.forms["kc-otp-login-form"].submit();
            }
            else
            {
                console.log("privacyIDEA:" + event.data);
                console.log("privacyIDEA: Poll transaction in browser failed. Please contact the administrator.");
                sessionStorage.removeItem("piResourcesPath");
                sessionStorage.removeItem("piServerURL");
                sessionStorage.removeItem("piTransactionID");

                // Fallback to standard poll transaction
                document.forms["kc-otp-login-form"].submit();
            }
        };
    }
}

function stopPollWorker()
{
    sessionStorage.setItem("pollInBrowserFailed", "true");
    w.terminate();
    w = undefined;
}