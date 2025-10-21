function bytesToBase64(bytes) {
    const binString = Array.from(bytes, (byte) =>
        String.fromCodePoint(byte),).join("");
    return btoa(binString);
}

function base64URLToBytes(base64URLString) {
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLength, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
}

function webAuthnAuthentication(signRequest, mode) {
    if (mode === "push") {
        changeMode("webauthn");
        return;
    }
    if (!signRequest) {
        console.log("WebAuthn Authentication: Challenge data is empty!")
        return "";
    }
    let signRequestObject = JSON.parse(signRequest.replace(/(&quot;)/g, "\""));
    try {
        const webAuthnSignResponse = window.pi_webauthn.sign(signRequestObject);
        webAuthnSignResponse.then((webauthnResponse) => {
            formResult.webAuthnSignResponse = JSON.stringify(webauthnResponse);
            submitForm();
        });
    } catch (err) {
        console.log(err);
    }
}

function passkeyAuthentication(passkeyChallenge, mode) {
    if (mode === "push") {
        changeMode("passkey");
        return;
    }
    if (!passkeyChallenge) {
        console.log("Passkey Authentication: Challenge data is empty!")
        return "";
    }
    formResult.passkeyLoginCancelled = false;
    let challengeObject = JSON.parse(passkeyChallenge.replace(/(&quot;)/g, "\""));
    let userVerification = "preferred";
    if (["required", "preferred", "discouraged"].includes(challengeObject.user_verification)) {
        userVerification = challengeObject.user_verification;
    }
    navigator.credentials.get({
        publicKey: {
            challenge: Uint8Array.from(challengeObject.challenge, c => c.charCodeAt(0)),
            rpId: challengeObject.rpId,
            userVerification: userVerification,
        },
    }).then(credential => {
        let params = {
            transaction_id: challengeObject.transaction_id,
            credential_id: credential.id,
            authenticatorData: bytesToBase64(
                new Uint8Array(credential.response.authenticatorData)),
            clientDataJSON: bytesToBase64(new Uint8Array(credential.response.clientDataJSON)),
            signature: bytesToBase64(new Uint8Array(credential.response.signature)),
            userHandle: bytesToBase64(new Uint8Array(credential.response.userHandle)),
        };
        formResult.passkeySignResponse = JSON.stringify(params);
        submitForm();
    }, function (error) {
        console.log("Passkey authentication error: " + error);
        formResult.passkeyLoginCancelled = true;
    });
}

// Use the passkey_registration from the response as input to this function
function registerPasskey(registrationData) {
    let data = JSON.parse(registrationData.replace(/(&quot;)/g, "\""));
    let excludedCredentials = [];
    if (data.excludeCredentials) {
        for (const cred of data.excludeCredentials) {
            excludedCredentials.push({
                id: base64URLToBytes(cred.id),
                type: cred.type,
            });
        }
    }

    return navigator.credentials.create({
        publicKey: {
            rp: data.rp,
            user: {
                id: base64URLToBytes(data.user.id),
                name: data.user.name,
                displayName: data.user.displayName
            },
            challenge: Uint8Array.from(data.challenge, c => c.charCodeAt(0)),
            pubKeyCredParams: data.pubKeyCredParams,
            excludeCredentials: excludedCredentials,
            authenticatorSelection: data.authenticatorSelection,
            timeout: data.timeout,
            extensions: {
                credProps: true,
            },
            attestation: data.attestation
        }
    }).then(function (publicKeyCred) {
        let params = {
            credential_id: publicKeyCred.id,
            rawId: bytesToBase64(new Uint8Array(publicKeyCred.rawId)),
            authenticatorAttachment: publicKeyCred.authenticatorAttachment,
            attestationObject: bytesToBase64(
                new Uint8Array(publicKeyCred.response.attestationObject)),
            clientDataJSON: bytesToBase64(new Uint8Array(publicKeyCred.response.clientDataJSON)),
        }
        if (publicKeyCred.response.attestationObject) {
            params.attestationObject = bytesToBase64(
                new Uint8Array(publicKeyCred.response.attestationObject));
        }
        const extResults = publicKeyCred.getClientExtensionResults();
        if (extResults.credProps) {
            params.credProps = extResults.credProps;
        }
        formResult.passkeyRegistrationResponse = JSON.stringify(params);
        submitForm();
    }, function (error) {
        console.log("Error while registering passkey:");
        console.log(error);
        return null;
    });
}

function requestPasskeyLogin() {
    formResult.passkeyLoginRequested = true;
    submitForm();
}

function authenticationReset() {
    formResult.authenticationResetRequested = true;
    submitForm();
}

function cancelEnrollmentViaMc() {
    formResult.enrollmentViaMultichallengeCancelled = true;
    submitForm();
}

function setPushReload(intervalSeconds) {
    if (!intervalSeconds) {
        console.log("Interval seconds is empty, using default of 2s.");
        intervalSeconds = 2;
    }
    window.setTimeout(() => {
        submitForm();
    }, parseInt(intervalSeconds) * 1000);
}

function setAutoSubmit(inputLength) {
    let otpField = document.querySelector("#otp")
    if (otpField) {
        otpField.addEventListener("keyup", function () {
            // catch parse int error?
            if (otpField.value.length === parseInt(inputLength)) {
                submitForm();
            }
        });
    }
}

function changeMode(newMode) {
    //console.log("changeMode to " + newMode);
    formResult.modeChanged = true;
    formResult.newMode = newMode;
    submitForm();
}

function submitForm() {
    if (!window.location.origin) {
        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':'
            + window.location.port : '');
    }
    formResult.origin = window.location.origin;
    //console.log("Submit, formResult:");
    //console.log(formResult);
    document.querySelector("#authenticationFormResult").value = JSON.stringify(formResult);
    document.forms["kc-otp-login-form"].requestSubmit();
}

function startPollingInBrowser(url, transactionId, resourcesPath) {
    let pushButton = document.querySelector("#pushButton");
    if (pushButton) {
        pushButton.style.display = "none";
    }
    let worker;
    if (typeof (Worker) !== "undefined") {
        if (typeof (worker) == "undefined") {
            worker = new Worker(resourcesPath + "/js/pi-pollTransaction.worker.js");
            let form = document.querySelector("#kc-login")
            if (form) {
                form.addEventListener('click', function (e) {
                    if (worker) {
                        worker.terminate();
                        worker = undefined;
                    }
                });
            }
            worker.postMessage({'cmd': 'url', 'msg': url});
            worker.postMessage({'cmd': 'transactionID', 'msg': transactionId});
            worker.postMessage({'cmd': 'start'});
            worker.addEventListener('message', function (e) {
                let data = e.data;
                switch (data.status) {
                    case 'success':
                        submitForm();
                        break;
                    case 'cancel':
                        formResult.pollInBrowserCancelled = true;
                        worker = undefined;
                        submitForm();
                        break;
                    case 'error':
                        console.log("Poll in Browser error: " + data.message);
                        formResult.pollInBrowserCancelled = true;
                        worker = undefined;
                        if (pushButton) {
                            pushButton.style.display = "initial";
                        }
                }
            });
        }
    } else {
        console.log("Poll in Browser error: The browser doesn't support WebWorker.");
        worker.terminate();
        formResult.pollInBrowserCancelled = true;
        formResult.pollInBrowserError = "The browser doesn't support WebWorker.";
        if (pushButton) {
            pushButton.style.display = "initial";
        }
    }
}

function setLoginOptionsVisibility() {
    let ids = ["passkeyInitiateButton", "otpButton", "pushButton", "webAuthnButton"]
    let shouldShow = false;
    for (let id of ids) {
        let element = document.querySelector("#" + id);
        if (element && window.getComputedStyle(element).display !== "none" && window.getComputedStyle(element).display !== "hidden") {
            shouldShow = true;
            break;
        }
    }
    if (!shouldShow) {
        let element = document.querySelector("#alternateToken");
        if (element) {
            element.style.display = "none";
        }
    }

    // If the otp input field is visible, hide the otp button
    let otpInput = document.querySelector("#otp");
    if (otpInput && otpInput.style.display !== "none" && otpInput.style.display !== "hidden") {
        let element = document.querySelector("#otpButton");
        if (element) {
            element.style.display = "none";
        }
    }
}