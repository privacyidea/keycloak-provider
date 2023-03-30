/**
 * Perform continuously the poll transaction in the browser until the server response with value: true.
 * @param {string} serverURL privacyIDEA server URL.
 * @param {string} transactionID Transaction ID needed to perform the poll transaction.
 * @returns {boolean} True by accepted request.
 */
function piPollTransaction(serverURL, transactionID)
{
    const url = serverURL + "/validate/polltransaction";
    const params = "transaction_id=" + transactionID;
    let success = false;
    do
    {
        const request = new XMLHttpRequest();
        request.open("GET", url + "?" + params, false);
        request.onload = (e) =>
        {
            if (request.readyState === 4)
            {
                if (request.status === 200)
                {
                    const response = JSON.parse(request.response);
                    console.log("response: " + response['result']['value']);
                    if (response['result']['value'])
                    {
                        console.log("privacyIDEA: polltransaction confirmed!");
                        success = true;
                    }
                }
                else
                {
                    console.error(request.statusText);
                    return false;
                }
            }
        };
        request.onerror = (e) =>
        {
            console.error(request.statusText);
            return false;
        };
        request.send();
    }
    while (success !== true)
    return true;
}