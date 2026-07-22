Java.perform(function () {
    console.log("Starting script...");

    // Hook all methods of a specific class
    function hookAllMethods(targetClass) {
        var hook = Java.use(targetClass);
        var methods = hook.class.getDeclaredMethods();
        hook.$dispose();

        methods.forEach(function (method) {
            var methodName = method.getName();
            var overloads = hook[methodName].overloads;
            overloads.forEach(function (overload) {
                overload.implementation = function () {
                    console.log(`[${targetClass}] ${methodName} called`);
                    // Log arguments
                    for (var i = 0; i < arguments.length; i++) {
                        console.log(`\targ[${i}]: ${arguments[i]}`);
                    }
                    // Call original method
                    var result = overload.apply(this, arguments);
                    console.log(`\treturn: ${result}`);
                    return result;
                };
            });
        });
    }

    // Hook 'ji' class methods
    setTimeout(function() {
        console.log("Hooking 'ji' class methods...");
        hookAllMethods("ji");
    }, 1000); // Adjust the delay as needed

    // Hook 'zn' class methods
    setTimeout(function() {
        console.log("Hooking network request methods in 'zn' class...");
        hookAllMethods("zn");
    }, 3000); // Adjust the delay as needed

    // Optionally, hook OkGo network methods if known
    setTimeout(function() {
        console.log("Hooking OkGo network methods...");
    
    }, 5000); // Adjust the delay as needed
});
