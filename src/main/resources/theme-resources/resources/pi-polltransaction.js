const url = sessionStorage.getItem("piServerURL") + "/validate/polltransaction";
const params = "transaction_id=" + sessionStorage.getItem("piTransactionID");
let success = false;
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
                    console.log("response json result->value: " + response['result']['value']); //todo rm
                    if (response['result']['value'])
                    {
                        success = true;
                        postMessage(true);
                        stopPollWorker();
                    }
                }
                else
                {
                    postMessage(request.statusText);
                    stopPollWorker();
                }
            }
        }
        catch (e)
        {
            postMessage(e);
            stopPollWorker();
        }
    };
    request.onerror = (e) =>
    {
        postMessage(request.statusText);
        stopPollWorker();
    };
    request.send();
}
console.log("doing poll transaction..."); //todo rm
setInterval("browserPollTransaction()", 2000);