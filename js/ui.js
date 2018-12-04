ObjC.schedule(ObjC.mainQueue, function(){
  	const window = ObjC.classes.UIWindow.keyWindow();
  	const ui = window.recursiveDescription().toString();
  	send({ ui: ui });
});

ObjC.schedule(ObjC.mainQueue, function(){
	const window = ObjC.classes.UIWindow.keyWindow();
	const rootControl = window.rootViewController();
	const control = rootControl['- _printHierarchy']();
	send({ ui: control.toString() });
});

function handleMessage(message) {

  var order = message.substring(0,1);
  var command = '';

  switch(order){
  	case 'n':
  		command = message.substring(2);
  		var view = new ObjC.Object(ptr(command));
	  	var nextResponder = view.nextResponder();
	  	nextResponder = new ObjC.Object(ptr(nextResponder));
	  	var deep = 0;
	  	var pre = '';
	  	while(nextResponder){
	    	pre += '-';
	      	send({ ui: pre+'>'+nextResponder.toString()});
	  		nextResponder = nextResponder.nextResponder();
	  		nextResponder = new ObjC.Object(ptr(nextResponder));
	  	}
  		break;
  	case 'a':
  		command = message.substring(2);
  		var view = new ObjC.Object(ptr(command));
  		var allTargets = view.allTargets();
  		var target = allTargets.allObjects().objectAtIndex_(0);
  		var allControlEvents = view.allControlEvents();
  		var af = view.actionsForTarget_forControlEvent_(target, allControlEvents);
  		send({ ui: '-> '+af.objectAtIndex_(0).toString()});
  		break;
  	case 'c':
  		command = message.substring(2);
  		var view = new ObjC.Object(ptr(command));
  		var allTargets = view.allTargets();
  		var count = allTargets.allObjects().count();
  		for(var i=0; i<count; i++){
  			send({ ui: '-> '+allTargets.allObjects().objectAtIndex_(i).toString()});
  		}
  		break;
  	default:
  		send({ ui: 'error command' });
  }
  recv(handleMessage);
}

recv(handleMessage);