const url = sessionStorage.getItem("piServerURL") + "/validate/polltransaction";
const params = "transaction_id=" + sessionStorage.getItem("piTransactionID");

function browserPollTransaction()
{
    const request = new XMLHttpRequest();
    request.open("GET", url + "?" + params, false);
    request.onload = (e) =>
    {
        try
        {
            if (request.readyState === 4)
            {
                if (request.status === 200)
                {
                    const response = JSON.parse(request.response);
                    if (response['result']['value'])
                    {
                        console.log("response json result->value: " + response['result']['value']); //todo rm
                        self.postMessage(true); //todo sending postMessage doesn't work! Fixing it will repair the whole flow. Maybe eventListener??
                        stopPollWorker();
                    }
                }
                else
                {
                    self.postMessage(request.statusText);
                    stopPollWorker();
                }
            }
        }
        catch (e)
        {
            self.postMessage(e);
            stopPollWorker();
        }
    };
    request.onerror = (e) =>
    {
        self.postMessage(request.statusText);
        stopPollWorker();
    };
    request.send();
}
setInterval("browserPollTransaction()", 2000);