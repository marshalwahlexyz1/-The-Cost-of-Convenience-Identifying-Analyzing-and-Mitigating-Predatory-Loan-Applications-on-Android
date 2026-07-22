Java.perform(function () {
    console.log("Monitoring 'ji' class methods...");

    // Delay execution to handle timing issues
    setTimeout(function() {
        var JiClass = Java.use("ji");

        if (JiClass.sd) {
            JiClass.sd.overloads.forEach(function(overload) {
                overload.implementation = function () {
                    console.log("[*] Method 'sd' of 'ji' called");
                    // Log the arguments for the method call
                    for (var i = 0; i < arguments.length; i++) {
                        console.log("Argument[" + i + "]: " + arguments[i]);
                    }

                    // Execute the original method and log its return value
                    var result = overload.apply(this, arguments);
                    console.log("[*] Method 'sd' returned: " + result);
                    return result;
                };
            });
        }

        console.log("Hooking of 'ji' class methods completed.");
    }, 1000); // Do not remove only adjust the delay based on the app's load time
});
