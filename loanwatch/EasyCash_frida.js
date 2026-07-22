Java.perform(function() {
  // Hook 1: SOURCE hook for ji.sd - captures call logs collection
  try {
    var ji = Java.use('ji');
    ji.sd.overload('android.content.Context').implementation = function(ctx) {
      console.log('ji.sd called with args: ' + JSON.stringify(arguments));
      var ret = this.sd(ctx);
      console.log('ji.sd returned: ' + ret);
      return ret;
    }
  } catch (e) {
    console.log('Error hooking ji.sd: ' + e);
  }

  setTimeout(function() {
    // Hook 2: SOURCE hook for ki.sd - captures call logs collection
    try {
      var ki = Java.use('ki');
      ki.sd.overload('android.content.Context').implementation = function(ctx) {
        console.log('ki.sd called with args: ' + JSON.stringify(arguments));
        var ret = this.sd(ctx);
        console.log('ki.sd returned: ' + ret);
        return ret;
      }
    } catch (e) {
      console.log('Error hooking ki.sd: ' + e);
    }

    setTimeout(function() {
      // Hook 3: DISPATCHER hook for zn.NC - captures packaged data being sent to network
      try {
        var zn = Java.use('zn');
        zn.NC.overload('zn$oE').implementation = function(arg) {
          console.log('zn.NC called with args: ' + JSON.stringify(arguments));
          this.NC(arg);
        }
      } catch (e) {
        console.log('Error hooking zn.NC: ' + e);
      }

      setTimeout(function() {
        // Hook 4: SINK hook for com.lzy.okgo.request.base.Request.execute - captures final network call
        try {
          var request = Java.use('com.lzy.okgo.request.base.Request');
          request.execute.implementation = function() {
            console.log('com.lzy.okgo.request.base.Request.execute called with args: ' + JSON.stringify(arguments));
            this.execute();
          }
        } catch (e) {
          console.log('Error hooking com.lzy.okgo.request.base.Request.execute: ' + e);
        }
      }, 100);
    }, 100);
  }, 100);
});