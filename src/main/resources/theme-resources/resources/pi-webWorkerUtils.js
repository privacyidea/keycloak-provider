let w;

function startPollWorker()
{
    if (typeof (Worker) !== "undefined")
    {
        if (typeof (w) == "undefined")
        {
            w = new Worker(sessionStorage.getItem("piResourcesPath") + "/pi-pollTransaction.js");
            console.log("Poll in browser: Setting new Worker...");
        }
        w.onmessage = function (event)
        {
            if (event.data === true)
            {
                console.log("Poll in browser: Poll transaction result succeeded!");
                document.forms["kc-otp-login-form"].submit();
            }
            else
            {
                console.log("Poll in browser error: " + event.data);
                console.log("Poll in browser failed. Please contact the administrator.");
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