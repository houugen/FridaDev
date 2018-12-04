// enumerate all Java classes
function enumAllClasses()
{
	var allClasses = [];
	var classes = Java.enumerateLoadedClassesSync();

	classes.forEach(function(aClass) {
		try {
			var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
		}
		catch(err) {} // avoid TypeError: cannot read property 1 of null
		allClasses.push(className);
	});

	return allClasses;
}

// find all Java classes that match a pattern
function findClasses(pattern)
{
	var allClasses = enumAllClasses();
	var foundClasses = [];

	allClasses.forEach(function(aClass) {
		try {
			if (aClass.match(pattern)) {
				foundClasses.push(aClass);
			}
		}
		catch(err) {} // avoid TypeError: cannot read property 'match' of undefined
	});

	return foundClasses;
}

// enumerate all methods declared in a Java class
function enumMethods(targetClass)
{
	var hook = Java.use(targetClass);
	var ownMethods = hook.class.getDeclaredMethods();
	hook.$dispose;

	return ownMethods;
}

// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		// enumerate all classes
		/*
		var a = enumAllClasses();
		a.forEach(function(s) { 
			console.log(s); 
		});
		*/

		// find classes that match a pattern
		/*
		var a = findClasses(/password/i);
		a.forEach(function(s) { 
			console.log(s); 
		});
		*/

		// enumerate all methods in a class
		/*
		var a = enumMethods("com.target.app.PasswordManager")
		a.forEach(function(s) { 
			console.log(s); 
		});
		*/

	});
}, 0);
