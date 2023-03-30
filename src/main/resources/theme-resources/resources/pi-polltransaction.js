/**
 * Perform continuously the poll transaction in the browser until the server response with value: true.
 * @param {string} serverURL privacyIDEA server URL.
 * @param {string} transactionID Transaction ID needed to perform the poll transaction.
 * @returns{boolean, void} True by accepted request, false if error.
 */
function piPollTransaction(serverURL, transactionID)
{
    const url = serverURL + "/validate/polltransaction";
    const params = "transaction_id=" + transactionID;
    let success = null;
    try
    {
        success = getResponse(url, params);
    }
    catch (e)
    {
        console.error(e);
        return false;
    }
    if (success === false)
    {
        return false;
    }
    if (success === true)
    {
        return true;
    }
}

function wait(ms)
{
    const start = Date.now();
    let now = start;
    while (now - start < ms)
    {
        now = Date.now();
    }
}

async function getResponse(url, params)
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
                console.log("response json false? : " + response['result']['value']); //todo rm
                if (response['result']['value'])
                {
                    return true;
                }
            }
            else
            {
                console.error(request.statusText);
                return false;
            }
            wait(2000);
        }
    };
    request.onerror = (e) =>
    {
        console.error(request.statusText);
        return false;
    };
    await request.send();
}