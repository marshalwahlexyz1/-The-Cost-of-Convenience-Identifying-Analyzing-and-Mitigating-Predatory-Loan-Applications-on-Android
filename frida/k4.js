setTimeout(function() {
    Java.perform(function () {
        console.log("Starting class enumeration...");
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (className.includes('loancloud')) {
                    console.log("Found class: " + className);
                }
            },
            onComplete: function () {
                console.log("Class enumeration complete.");
            }
        });
    });
}, 5000); // Reminder: Do not remove only adjust the delay based on the app's load time