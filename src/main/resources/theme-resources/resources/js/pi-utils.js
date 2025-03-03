window.piGetValue = function getValue(id) {
    const element = document.getElementById(id);
    if (element !== null) {
        return element.value;
    } else {
        console.log(id + " is null!");
        return "";
    }
}

window.piSetValue = function setValue(id, value) {
    const element = document.getElementById(id);
    if (element !== null) {
        element.value = value;
    } else {
        console.log(id + " is null!");
    }
}

window.piDisableElement = function disableElement(id) {
    const element = document.getElementById(id);
    if (element !== null) {
        element.style.display = "none";
    } else {
        console.log(id + " is null!");
    }
}

window.piEnableElement = function enableElement(id) {
    const element = document.getElementById(id);
    if (element !== null) {
        element.style.display = "initial";
    } else {
        console.log(id + " is null!");
    }
}