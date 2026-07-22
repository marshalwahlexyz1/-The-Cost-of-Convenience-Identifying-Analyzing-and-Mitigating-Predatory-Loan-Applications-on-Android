Java.perform(function () {
    console.log("Starting script...");

    function logArgumentsAndResult(className, methodName, args, result) {
        console.log(`[${className}] ${methodName} called`);
        for (let i = 0; i < args.length; i++) {
            console.log(`\targ[${i}]: ${args[i]}`);
        }
        console.log(`\treturn: ${result}`);
    }

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

    // Hook 'ji' class methods
    setTimeout(function () {
        console.log("Hooking 'ji' class methods...");
        hookMethod("ji", "sd", [["android.content.Context", "java.lang.String"]]); // Adjust the method signatures as needed
    }, 1000);

    // Hook 'zn' class methods
    setTimeout(function () {
        console.log("Hooking 'zn' class methods...");
        hookMethod("zn", "NC", [
            ["zn$oE"],
            ["java.lang.String", "zn$oE"],
            ["android.content.Context", "java.lang.String", "zn$oE"]
        ]);
        // Additional hooking to log network request URLs and parameters
        Java.use("zn$sd").onSuccess.implementation = function (response) {
            console.log("Network request onSuccess called");
            console.log(`Response code: ${response.code()}`);
            console.log(`Response body: ${response.body()}`);
            this.onSuccess(response);
        };
    }, 3000);
});
