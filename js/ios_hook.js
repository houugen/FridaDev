function findHookMethod(clsname, mtdname){
    if(ObjC.available) {
        for(var className in ObjC.classes) {
            if (ObjC.classes.hasOwnProperty(className)) {
                if(className == clsname) {
                    return ObjC.classes[className][mtdname];
                }
            }
        }
    }
    return;
}

var method = findHookMethod('FireflySecurityUtil', '+ aesEncrypt:key:vector:');
Interceptor.attach(method.implementation, {
    onEnter:function (args){
        console.log('+[FireflySecurityUtil aesEncrypt:key:vector:] onEnter...');
        this.body = (new ObjC.Object(args[2])).toString();
        this.key = (new ObjC.Object(args[3])).toString();
        this.iv = (new ObjC.Object(args[4])).toString();
        console.log('data: ' + this.body);
        console.log('key: ' + this.key);
        console.log('iv: ' + this.iv);
    },
    onLeave:function(retVal){
        console.log('+[FireflySecurityUtil aesEncrypt:key:vector:] onLeave...');
        console.log('ret: ' + (new ObjC.Object(retVal)).toString());
        var retdata = ObjC.classes.NSString.stringWithString_(this.body);
        retVal.replace(retdata);
    }
});
