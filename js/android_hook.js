function clearzero(array,len){
    var result = new Array();
    for (var i = 0; i < len; ++i) {
        result[i] = array[i];
    }
    return result;
}

function bin2string(array){
    var result = "";
    for(var i = 0; i < array.length; ++i){
        result+= (String.fromCharCode(array[i]));
    }
    return result;
}

/*
    ----------------- hook java -------------------
 */
Java.perform(function () {
    var hookClass = Java.use("com.pengbo.commutils.fileutils.PbLog");
    hookClass.setLogCat.implementation = function(s1) {
        send('hook setLogCat');
        // throw Exception.$new("exception");
        this.setLogCat(true);
    };
    var hookClass = Java.use("com.pengbo.pbmobile.PbMobileApplication");
    hookClass.onCreate.implementation = function() {
        send('hook onCreate');
        this.onCreate();
    };
});

/*
    ----------------- hook native -------------------
 */
var libaddr = Module.findBaseAddress('libyyb_cscomm.so');
console.log('libyyb_cscomm.so address: ' + libaddr);
var uncompress = libaddr.add(0x58C8)
console.log('uncompress: ' + uncompress)
var decryptResponse = null;

Module.enumerateExports("libyyb_cscomm.so", {
    onMatch: function(exp) {
        if(exp.name == 'decryptResponse') {
            decryptResponse = exp.address;
            console.log('decryptResponse: ' + exp.address);
        }
    },
    onComplete: function() {
    }
});

Interceptor.attach(decryptResponse, {
    onEnter: function (args) {
        console.log(args[0]);
        var buf = Memory.readByteArray(args[2], 128);
        console.log(hexdump(buf, {
          offset: 0,
          length: 128,
          header: true,
          ansi: true
        }));
    },
    onLeave: function (retval) {
    }
});