// enumerate all ObjC classes
function enumAllClasses()
{
	var allClasses = [];

	for (var aClass in ObjC.classes) {
		if (ObjC.classes.hasOwnProperty(aClass)) {
			allClasses.push(aClass);
		}
	}

	return allClasses;
}

// find all ObjC classes that match a pattern
function findClasses(pattern)
{
	var allClasses = enumAllClasses();
	var foundClasses = [];

	allClasses.forEach(function(aClass) {
		if (aClass.match(pattern)) {
			foundClasses.push(aClass);
		}
	});

	return foundClasses;
}

// enumerate all methods declared in an ObjC class
function enumMethods(targetClass)
{
	var ownMethods = ObjC.classes[targetClass].$ownMethods;

	return ownMethods;
}

// enumerate all methods declared in all ObjC classes
function enumAllMethods()
{
	var allClasses = enumAllClasses();
	var allMethods = {}; 

	allClasses.forEach(function(aClass) {
		enumMethods(aClass).forEach(function(method) {
			if (!allMethods[aClass]) allMethods[aClass] = [];
			allMethods[aClass].push(method);
		});
	});

	return allMethods;
}

// find all ObjC methods that match a pattern
function findMethods(pattern)
{
	var allMethods = enumAllMethods();
	var foundMethods = {};

	for (var aClass in allMethods) {
		allMethods[aClass].forEach(function(method) {
			if (method.match(pattern)) {
				if (!foundMethods[aClass]) foundMethods[aClass] = [];
				foundMethods[aClass].push(method);
			}
		});
	}

	return foundMethods;
}

// usage examples
if (ObjC.available) {

	// enumerate all classes
	/*
	var a = enumAllClasses();
	a.forEach(function(s) { 
		console.log(s); 
	});
	*/

	// find classes that match a pattern
	/*
	var a = findClasses(/FireflySecurityUtil/i);
	a.forEach(function(s) { 
		console.log(s); 
	});
	*/

	// enumerate all methods in a class
	/*
	var a = enumMethods("CGBLoginViewController")
	a.forEach(function(s) { 
		console.log(s); 
	});
	*/

	// enumerate all methods
	/*
	var d = enumAllMethods();
	for (k in d) {
		console.log(k);
		d[k].forEach(function(s) {
			console.log("\t" + s);
		});
	}
	*/

	// find methods that match a pattern
	
	var d = findMethods(/encrypt|decrypt/i);
	for (k in d) {
		console.log(k);
		d[k].forEach(function(s) {
			console.log("\t" + s);
		});
	}
} else {
 	send("error: Objective-C Runtime is not available!");
}
