let url;
let params;

self.addEventListener('message', function (e) {
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
                setInterval(function () {
                    fetch(url + "?" + params, { method: 'GET' })
                        .then(r => {
                            if (r.ok)
                            {
                                r.text().then(result => {
                                    const resultJson = JSON.parse(result);
                                    if (resultJson['detail']['challenge_status'] === "accept")
                                    {
                                        self.postMessage({
                                                             'message': 'Polling in browser: Push message confirmed!',
                                                             'status': 'success'
                                                         });
                                        self.close();
                                    }
                                    else if (resultJson['detail']['challenge_status'] === "declined")
                                    {
                                        self.postMessage({
                                                             'message': 'Polling in browser: Authentication declined!',
                                                             'status': 'cancel'
                                                         });
                                        self.close();
                                    }
                                });
                            }
                            else
                            {
                                self.postMessage({ 'message': r.statusText, 'status': 'error' });
                                self.close();
                            }
                        })
                        .catch(e => {
                            self.postMessage({ 'message': e, 'status': 'error' });
                            self.close();
                        });
                }, 300);
            }
            break;
    }
});