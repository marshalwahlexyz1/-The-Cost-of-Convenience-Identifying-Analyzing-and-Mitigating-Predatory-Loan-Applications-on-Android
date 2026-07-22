Java.perform(function () {
    console.log("Starting script...");

    // Utility function to log method calls
    function logArgumentsAndResult(className, methodName, args, result) {
        console.log(`[${className}] ${methodName} called`);
        for (let i = 0; i < args.length; i++) {
            console.log(`\targ[${i}]: ${args[i]}`);
        }
        console.log(`\treturn: ${result}`);
    }

    // Generic method hooking
    function hookMethod(className, methodName, overloads) {
        var targetClass = Java.use(className);
        overloads.forEach(function (signature) {
            targetClass[methodName].overload.apply(targetClass[methodName], signature).implementation = function () {
                var args = [].slice.call(arguments);
                var result = this[methodName].apply(this, args);
                logArgumentsAndResult(className, methodName, args, result);
                return result;
            };
        });
    }

    // Hooking 'ji' class methods
    setTimeout(function () {
        console.log("Hooking 'ji' class methods...");
        hookMethod("ji", "sd", [["android.content.Context", "java.lang.String"]]);
    }, 1000);

    // Hooking 'zn' class methods and network requests
    setTimeout(function () {
        console.log("Hooking 'zn' class methods...");
        hookMethod("zn", "NC", [
            ["zn$oE"],
            ["java.lang.String", "zn$oE"],
            ["android.content.Context", "java.lang.String", "zn$oE"]
        ]);

        // Hook onSuccess method in 'zn$sd' class to log network responses
        var znSdClass = Java.use("zn$sd");
        znSdClass.onSuccess.implementation = function (response) {
            console.log("Network request onSuccess called");
            console.log(`Response code: ${response.code()}`);
            console.log(`Response body: ${response.body()}`);
            return this.onSuccess(response);
        };
    }, 1000);

    // Hooking network requests in OkGo library
    setTimeout(function() {
        console.log("Hooking OkGo network methods...");
        var postRequestClass = Java.use("com.lzy.okgo.request.PostRequest");
        postRequestClass.generateRequest.implementation = function (requestBody) {
            var request = this.generateRequest(requestBody);
            console.log("[PostRequest] Request URL:", request.url().toString());
            console.log("[PostRequest] Request Method:", request.method());
            console.log("[PostRequest] Request Body:", requestBody); // requestBody might need to be stringified or further parsed
            return request;
        };
    }, 1000);
});
