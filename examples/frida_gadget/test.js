console.log("Hello from your Goauld named Frida");

Interceptor.attach(Module.getExportByName(null, 'write'), {
  onEnter: function (args) {
    var buff = args[1].readUtf8String();
    console.log('write() buff="' + buff + '"');
  },
  onLeave: function (retval) {
    var ssize = retval.toInt32();
    console.log('write()) => size=' + ssize);
  }
});