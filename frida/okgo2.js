Java.perform(function () {
    setTimeout(function() {
        var jiClass = Java.use("ji");
        var znClass = Java.use("zn");
        var postRequestClass = Java.use("com.lzy.okgo.request.PostRequest");

        // Hook the 'sd' method in 'ji' class
        if (jiClass.sd) {
            jiClass.sd.overload('android.content.Context', 'java.lang.String').implementation = function (context, data) {
                console.log("[ji] sd called with data:", data);
                var result = this.sd(context, data);
                console.log("[ji] sd returned:", result);
                return result;
            };
        }

        // Hook the 'NC' method in 'zn' class
        znClass.NC.overload('zn$oE').implementation = function (oEInstance) {
            console.log("[zn] NC called with zn$oE instance:", oEInstance);
            var result = this.NC(oEInstance);
            console.log("[zn] NC returned:", result);
            return result;
        };

        // Hook the generateRequest method in PostRequest class
        postRequestClass.generateRequest.implementation = function (requestBody) {
            console.log("[PostRequest] generateRequest called with requestBody:", requestBody);
            var request = this.generateRequest(requestBody);
            console.log("[PostRequest] Request URL:", request.url().toString());
            console.log("[PostRequest] Request Method:", request.method());
            console.log("[PostRequest] Request Body:", requestBody); // requestBody might need to be stringified or further parsed
            return request;
        };

    }, 1000); // Delay to ensure class loading
});
