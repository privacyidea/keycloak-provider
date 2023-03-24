/**
 * Perform continuously the poll transaction in the browser until the server response with value: true.
 * @param {string} serverURL privacyIDEA server URL.
 * @param {string} transactionID Transaction ID needed to perform the poll transaction.
 * @returns {boolean} True by accepted request.
 */
function piPollTransaction(serverURL, transactionID) {
    const url = serverURL + "/validate/polltransaction";
    const params = "transaction_id=" + transactionID;
    const request = new XMLHttpRequest(); // todo "C:\Program Files\Google\Chrome\Application\chrome.exe" --ignore-certificate-errors --user-data-dir="c:/chrome_dev_session"
    request.
    request.open("GET", url + "?" + params, true);
    let success = false;
    do {
        // todo try catch (SSL exception)
        request.send();
        if (request.status === 200) {
            const response = JSON.parse(request.response);
            if (response['result']['value']) {
                success = true;
            } else {
                console.log('Push not confirmed yet...');
                wait(2000);
            }
        } else {
            console.log(`error ${request.status}`)
            return false;
        }
    }
    while (success === true)
    return success;
}

/** @param ms */
function wait(ms) {
    const start = Date.now();
    let now = start;
    while (now - start < ms) {
        now = Date.now();
    }
}