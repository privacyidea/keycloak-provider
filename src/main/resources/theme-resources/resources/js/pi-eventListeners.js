function eventListeners() {
    // POLL IN BROWSER
    if (piGetValue("pollInBrowserUrl").length > 0 && piGetValue("transactionID").length > 0) {
        piDisableElement("pushButton");
        let worker;
        if (typeof (Worker) !== "undefined") {
            if (typeof (worker) == "undefined") {
                worker = new Worker(piGetValue("resourcesPath") + "/js/pi-pollTransaction.worker.js");
                document.getElementById("kc-login").addEventListener('click', function (e) {
                    worker.terminate();
                    worker = undefined;
                });
                worker.postMessage({'cmd': 'url', 'msg': piGetValue("pollInBrowserUrl")});
                worker.postMessage({'cmd': 'transactionID', 'msg': piGetValue("transactionID")});
                worker.postMessage({'cmd': 'start'});
                worker.addEventListener('message', function (e) {
                    let data = e.data;
                    switch (data.status) {
                        case 'success':
                            submitForm();
                            break;
                        case 'cancel':
                            piSetValue("pollInBrowserDeclined", true);
                            worker = undefined;
                            submitForm();
                            break;
                        case 'error':
                            console.log(piGetValue("pollInBrowserErrorMsg") + data.message);
                            piSetValue("errorMessage", "Poll in browser error: " + data.message);
                            piSetValue("pollInBrowserFailed", true);
                            piEnableElement("pushButton");
                            worker = undefined;
                    }
                });
            }
        } else {
            console.log(piGetValue("noWebWorkerSupportMsg"));
            worker.terminate();
            piSetValue("errorMessage", "Poll in browser error: The browser doesn't support the Web Worker.");
            piSetValue("pollInBrowserFailed", true);
            piEnableElement("pushButton");
        }
    }
}

// Wait until the document is ready
document.addEventListener("DOMContentLoaded", function () {
    eventListeners();
});