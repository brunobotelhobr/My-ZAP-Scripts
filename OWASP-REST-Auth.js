// The authenticate function will be called for authentications made via ZAP.

// The authenticate function is called whenever ZAP requires to authenticate, for a Context for which this script
// was selected as the Authentication Method. The function should send any messages that are required to do the authentication
// and should return a message with an authenticated response so the calling method.
//
// Parameters:
//    helper - a helper class providing useful methods: prepareMessage(), sendAndReceive(msg), getHttpSender()
//    paramsValues - the values of the parameters configured in the Session Properties -> Authentication panel.
//          The paramsValues is a map, having as keys the parameters names (as returned by the getRequiredParamsNames()
//          and getOptionalParamsNames() functions below)
//    credentials - an object containing the credentials values, as configured in the Session Properties -> Users panel.
//          The credential values can be obtained via calls to the getParam(paramName) method. The param names are the ones
//          returned by the getCredentialsParamsNames() below

function authenticate(helper, paramsValues, credentials) {
	// Imports
	var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');

	var AuthenticationHelper = Java.type('org.zaproxy.zap.authentication.AuthenticationHelper');
	var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
	var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
	var URI = Java.type("org.apache.commons.httpclient.URI");

	logger("Authenticating via JavaScript script...");

	// Example URL
	// http://localhost:8080/login
	var loginUrl = paramsValues.get("Login URL");

	// Post Data, replace variables  "%username%" and "%password%"
	// Example {"user": "%username%","pass": "%password%"}
	var postData = paramsValues.get("POST Data");

	logger("Got Login URL " + loginUrl);
	logger("Got Post Data " + postData);

	// Replace user and pass in postData
	postData = postData.replace('%username%', credentials.getParam("username"));
	postData = postData.replace('%password%', credentials.getParam("password"));
	logger("Replaced Post Data " + postData);

	// Build message.
	var RequestURI = new URI(loginUrl, false);
	logger("Request URI " + RequestURI);

	// Craft a HTTP Request 
	var RequestMethod = HttpRequestHeader.POST;
	var RequestMainHeader = new HttpRequestHeader(RequestMethod, RequestURI, HttpHeader.HTTP11);
	var msg = helper.prepareMessage();
	msg.setRequestBody(postData);
	msg.setRequestHeader(RequestMainHeader)
	msg.getRequestHeader().setHeader(HttpHeader.REFERER, loginUrl);
	msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
	msg.getRequestHeader().setHeader('Content-Type', "application/json");
	msg.getRequestHeader().setHeader('Accept', "application/json");

	// Send message and receive response
	logger("Sending message...");
	helper.sendAndReceive(msg, false);

	// Check the response is Good
	var statusCode = msg.getResponseHeader().getStatusCode();
	logger("Authentication Status: " + statusCode);

	// Parse the response
	logger("Handling auth response")
	var resbody = msg.getResponseBody().toString()
	var resheaders = msg.getResponseHeader()

	// Check if the response has a good status code
	if (resheaders.getStatusCode() > 299) {
		logger("Auth failed");
		// Add message to ZAP history.
		AuthenticationHelper.addAuthMessageToHistory(msg);
		return;

		// Is response JSON? @todo check content-type
		if (resbody[0] !== '{') {
			logger("Null Body");
			// Add message to ZAP history.
			AuthenticationHelper.addAuthMessageToHistory(msg);
			return;
		}
		try {
			var data = JSON.parse(resbody);
		} catch (e) {
			// Add message to ZAP history.
			logger("No JSON in response");
			AuthenticationHelper.addAuthMessageToHistory(msg);
			return;
		}
	}

	//Extracting Token
	// Other Example var token = data["authentication"]["token"]
	var data = JSON.parse(resbody);
	var token = data["access_token"];
	logger("Capturing token for JWT\n" + token);

	// Set Token by Cookie
	//msg.getResponseHeader().setHeader('Set-Cookie', 'token=' + token);

	// Set Token Global Variable
	ScriptVars.setGlobalVar("jwt-token", token)

	// Add message to ZAP history.
	AuthenticationHelper.addAuthMessageToHistory(msg);

	return msg;
}

// This function is called during the script loading to obtain a list of the names of the required configuration parameters,
// that will be shown in the Session Properties -> Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getRequiredParamsNames() {
	logger("Get Required Params Names");
	return ["Login URL", "POST Data"];
}

// This function is called during the script loading to obtain a list of the names of the optional configuration parameters,
// that will be shown in the Session Properties -> Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getOptionalParamsNames() {
	logger("Get Optional Params Names");
	return [];
}

// This function is called during the script loading to obtain a list of the names of the parameters that are required,
// as credentials, for each User configured corresponding to an Authentication using this script 
function getCredentialsParamsNames() {
	logger("Get Credentials Params Names");
	return ["username", "password"];
}

// This optional function is called during the script loading to obtain the logged in indicator.
// NOTE: although optional this function must be implemented along with the function getLoggedOutIndicator().
//function getLoggedInIndicator() {
//  return "LoggedInIndicator";
//}

// This optional function is called during the script loading to obtain the logged out indicator.
// NOTE: although optional this function must be implemented along with the function getLoggedInIndicator().
//function getLoggedOutIndicator() {
//  return "LoggedOutIndicator";
//}
// My Logger Function
function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}