Java.perform(function () {
    setTimeout(function() {
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (className.includes("ji")) {
                    console.log("Found class: " + className);
                    try {
                        var ContactManager = Java.use(className);
                        // Hook a specific method if known
                        if (ContactManager.sd && typeof ContactManager.sd.overload === 'function') {
                            ContactManager.sd.overload('android.content.Context').implementation = function (context) {
                                console.log(className + ".sd(Context) called");
                                var result = this.sd(context);
                                // Additional logic to log or modify the result if needed
                                return result;
                            };
                        }
                    } catch (e) {
                        console.error("Error hooking class " + className + ": " + e.message);
                    }
                }
            },
            onComplete: function () {
                console.log("Class enumeration complete.");
            }
        });
    }, 5000); // Do not remove only adjust the delay to allow app to fully load and classes to be available
});
