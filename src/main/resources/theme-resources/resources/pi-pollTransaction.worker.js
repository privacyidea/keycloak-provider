let url;
let params;
self.addEventListener('message', function (e)
{
    let data = e.data;
    switch (data.cmd)
    {
        case 'url':
            url = data.msg + "/validate/polltransaction";
            break;
        case 'transactionID':
            params = "transaction_id=" + data.msg;
            break;
        case 'start':
            if (url.length > 0 && params.length > 0)
            {
                self.postMessage({'message': 'Trying to poll in the browser...', 'status': 'progress'})
                setInterval("pollTransactionInBrowser()", 2000);
            }
            break;
    }
})

function pollTransactionInBrowser()
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
                    self.postMessage({'message': 'Polling in browser: Bound with the privacyIDEA server.', 'status': 'progress'});
                    if (response['result']['value'] === true)
                    {
                        self.postMessage({'message': 'Polling in browser: Push message confirmed!', 'status': 'success'});
                        self.close();
                    }
                    else if (response['result']['value'] === false)
                    {
                        self.postMessage({'message': 'Polling in browser: Push not accepted yet...', 'status': 'progress'});
                    }
                }
                else
                {
                    self.postMessage({'message': request.statusText, 'status': 'error'});
                    self.close();
                }
            }
        }
        catch (e)
        {
            self.postMessage({'message': e, 'status': 'error'});
            self.close();
        }
    };
    request.onerror = (e) =>
    {
        self.postMessage({'message': request.statusText, 'status': 'error'});
        self.close();
    };
    request.send();
}