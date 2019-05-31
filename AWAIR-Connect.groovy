/**
 *  AWAIR Air Quality Monitor
 *
 *  Copyright 2019 Darren Donnelly
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */
 
definition(
    name: "AWAIR V2 (Connect)",
    namespace: "DarrenD05",
    author: "Darren Donnelly",
    description: "Virtual Device Handler for AWAIR Air Quality Monitor",
    category: "My Apps",
    iconUrl: "https://cdn.shopify.com/s/files/1/1439/3986/t/6/assets/favicon.png?583879",
    iconX2Url: "https://cdn.shopify.com/s/files/1/1439/3986/t/6/assets/favicon.png?583879",
    iconX3Url: "https://cdn.shopify.com/s/files/1/1439/3986/t/6/assets/favicon.png?583879",
    singleInstance: false)
 
{
    appSetting "client_id"
    appSetting "client_secret"
}

mappings {
    path("/oauth/initialize") {action: [GET: "oauthInitUrl"]}
    path("/oauth/callback") {action: [GET: "callback"]}
}

preferences {
	page(name: "auth", title: "AWAIR", content:"authPage", install:false)
    page(name: "selectDevices", title: "Device Selection", content:"selectDevicesPage", install:false)
    page(name: "settings", title: "Settings", content: "settingsPage", install:true)
    }

private String APIKey() {return appSettings.client_id}
private String APISecret() {return appSettings.client_secret}
def getChildName() { return "AWAIR Air Quality Monitor" }

def installed() {
    log.info "Installed with settings: ${settings}"
    initialize()
}

def updated() {
    log.info "Updated with settings: ${settings}"

    unsubscribe()
    initialize()
}

def uninstalled() {
    def delete = getAllChildDevices()
    delete.each { deleteChildDevice(it.deviceNetworkId) }
}

def initialize() {
	log.debug "Entering the initialize method"

		def d = getChildDevice(dni)
		if(!d) {
        	def devlist = atomicState.devices
			d = addChildDevice(app.namespace, getChildName(), dni, null, ["label":"${devlist[dni]} Lyric" ?: "AWAIR Air Quality Monitor"])
			log.info "created ${d.displayName} with id $dni"
		} else {
			log.info "found ${d.displayName} with id $dni already exists"
		}
		return d
	
    
	//log.debug "created ${devs.size()} devices."

	def delete  // Delete any that are no longer in settings
	if(!devs) {
		//log.debug "delete all leak sensors"
		delete = getAllChildDevices() //inherits from SmartApp (data-management)
	} else {
		//log.debug "delete individual thermostat and sensor"
		delete = getChildDevices().findAll { !settings.devices.contains(it.deviceNetworkId)}
	}
	log.warn "delete: ${delete}, deleting ${delete.size()} leak sensors"
	delete.each { deleteChildDevice(it.deviceNetworkId) } //inherits from SmartApp (data-management)
	
    try{
    	pollChildren()
    }
    catch (e)
    {
    	log.debug "Error with initial polling: $e"
    }
    
	runEveryMinute("pollChildren")

}



/////////////////////API AUTH INFORMATION///////////////////////////////

def authPage() {
    if(!atomicState.accessToken) {
        // the createAccessToken() method will store the access token in atomicState.accessToken
        createAccessToken()
        atomicState.accessToken = state.accessToken
    }
    
    def description
    def uninstallAllowed = false
    def oauthTokenProvided = false

    if(atomicState.authToken) {
        description = "You are connected."
        uninstallAllowed = true
        oauthTokenProvided = true
    } else {
        description = "Click to enter AWAIR Credentials"
    }

    def redirectUrl = "https://graph.api.smartthings.com/oauth/initialize?appId=${app.id}&access_token=${atomicState.accessToken}&apiServerUrl=${getApiServerUrl()}"
    // Check to see if SmartThings already has an access token from the third-party service.
    if(!oauthTokenProvided) {
    	log.debug "Redirect URL (authPage) ${redirectUrl}"
        if (!oauthTokenProvided) {
            return dynamicPage(name: "auth", title: "Login", nextPage: "", uninstall:uninstallAllowed) {
                section("") {
                    paragraph "Tap below to log in to the AWAIR service and authorize SmartThings access."
                    href url:redirectUrl, style:"embedded", required:true, title:"AWAIR", description:description
                }
            }
        }
    } else {
        def devices = selectDevicesPage()
        def devs = [:]
        devs += selectDevicesPage()
		atomicState.devices = devs
        log.debug "available devices list: ${devs}"
        return dynamicPage(name: "auth", title: "Select Your Device", nextPage: "settings", uninstall:uninstallAllowed) {
            section("") {
                paragraph "Tap below to see the list of devices available in your AWAIR account and select the ones you want to connect to SmartThings."
                input(name: "Devices", title:"Select Your Device(s)", type: "enum", required:true, multiple:true, description: "Tap to choose", metadata:[values:devs])
            }
        }
    }
}

private settingsPage(){
    return dynamicPage(name: "settings", title: "Settings", nextPage: "", uninstall:false, install:true) {
                section("") {
                    input "DisplayTempInF", "boolean", title: "Display temperatures in Fahrenheit?", defaultValue: true, required: false
                }
            }
}
def oauthInitUrl() {

    // Generate a random ID to use as a our state value. This value will be used to verify the response we get back from the third-party service.
    atomicState.oauthInitState = UUID.randomUUID().toString()

    def oauthParams = [
        response_type: "code",
        scope: "smartRead,smartWrite",
        client_id: APIKey(),
        client_secret: APISecret(),
        state: atomicState.oauthInitState,
        redirect_uri: "https://graph.api.smartthings.com/oauth/callback"
    ]
	log.debug "Redirecting to ${"https://oauth-login.awair.is"}?${toQueryString(oauthParams)}"
    redirect(location: "${"https://oauth-login.awair.is"}?${toQueryString(oauthParams)}")
}

String toQueryString(Map m) {
        return m.collect { k, v -> "${k}=${URLEncoder.encode(v.toString())}" }.sort().join("&")
}

def callback() {
    log.debug "callback()>> params: $params, params.code ${params.code}"

    def code = params.code
    def oauthState = params.state

    // Validate the response from the third party by making sure oauthState == atomicState.oauthInitState as expected
    if (oauthState == atomicState.oauthInitState){
        def Params = [
        	uri: "https://oauth2.awair.is",
            path: "/v2/token",
        	headers: ['Authorization': "Bearer ${getBase64AuthString()}"],
            body: [
            	grant_type: "authorization_code",
            code      : code.toString(),
            client_id : APIKey(),
            client_secret: APISecret(),
            redirect_uri: "https://graph.api.smartthings.com/oauth/callback"
            ],
        ]
        
        try {
            httpPost(Params) { resp ->
                log.debug "refresh auth token response data: ${resp.data}"
                atomicState.tokenExpiresIn = resp.data.expires_in
                atomicState.refreshToken = resp.data.refresh_token
                atomicState.authToken = resp.data.access_token
            }
        } 
        catch (e) {
            log.error "Error in the callback method: $e"
        }

        if (atomicState.authToken) {
            // call some method that will render the successfully connected message
            success()
        } else {
            // gracefully handle failures
            fail()
        }

    } else {
        log.error "callback() failed. Validation of state did not match. oauthState != atomicState.oauthInitState"
    }
}

private String getBase64AuthString() {
    String authorize = "${APIKey()}:${APISecret()}"
    String authorize_encoded = authorize.bytes.encodeBase64()
    return authorize_encoded
}

private refreshAuthToken() {
		if (testAuthToken() == false) {
            log.info "Refreshing your auth_token!"
            def Params = [
                uri: "https://oauth2.awair.is",
            path: "/v2/token",
                headers: ['Authorization': "Bearer ${getBase64AuthString()}"],
                body: [
                    grant_type: 'refresh_token',
                    refresh_token: atomicState.refreshToken
                ],
            ]

            try {
                httpPost(Params) { resp ->
                    log.debug resp.data
                    if(resp.status == 200)
                    {
                        if (resp.data) {
                            atomicState.refreshToken = resp?.data?.refresh_token
                            atomicState.authToken = resp?.data?.access_token
                            atomicState.tokenExpiresIn = resp?.data?.expires_in
                            log.info "Token refresh Success."
                        }
                    }}
            }
            catch (e) {
                log.error "Error in the refreshAuthToken method: $e"
            }

    }
}

private testAuthToken() {
        def Params = [
        	uri: "https://oauth2.awair.is",
            path: "/v2/token",
        	headers: ['Authorization': "Bearer ${atomicState.authToken}"],
            query: [
                apikey: APIKey()
            ],
        ]
        
        try {
           httpGet(Params) { resp -> 
            //log.debug "testAuthToken response: ${resp}"
           	if(resp.status == 200) {
            	log.info "Auth code test success. Status: ${resp.status}"
            	return true
            }
            else {
            	log.warn "Status != 200 while testing current auth code. Response=${resp.data}, Status: ${resp.status}"
				return false
            }
           }
        }
            catch (e) {
            	log.error "Error while testing auth code: $e"
            	return false
        	}
}

///////////////////////////////////////////////////////////////DEVICE DISCOVER INFORMATION////////////////////////////////////////////////////////////////////////////////
def selectDevicesPage() {
    def params = [
        uri: "https://developer-apis.awair.is",
        path: "/v1/users/self/devices",
        ContentType: "application/json",
      	headers: ['Authorization': "Bearer ${atomicState.authToken}", 'Accept':'application/json'],
    ]
    
    	  def devs = [:]
        def deviceids = [:]
        try {
            httpGet(params) { resp ->
            log.debug "Response Data: ${resp.data}"
            log.debug "Response IDs: ${resp.data.devices.deviceId}"
            log.debug "Response Names: ${resp.data.devices.name}"
            log.debug "Response Device Type: ${resp.data.devices.deviceType}"
            
                if(resp.status == 200)
                {	
                    resp.data.devices.each { dev ->
                    try{
                        def dni = [app.id, dev.deviceId].join('.')
                        log.debug "Found device ID: ${dni} Name: ${dev.name}"
                        devs[dni] = dev.name
                        deviceids[dni] = dev.deviceId
                        }
                     catch (e) {
                        log.error "Error in getDevices: $e"
                     }
				}
                } 
            }
            atomicState.deviceids = deviceids
            atomicState.devices = devs
          }
        catch (e) {
            log.error "Error in getDevices: $e"
        }
        return devs
}


///////////////////////////////////////SMARTAPP INFORMATION///////////////////////////////////////////////////////

def success() {
        def message = """
                <p><h1>Your account is now connected to SmartThings!</h1></p>
                <p><h2>Click 'Done' to finish setup.</h2></p>
        """
        displayMessageAsHtml(message)
}

def fail() {
    def message = """
        <p>There was an error connecting your account with SmartThings</p>
        <p>Please try again.</p>
    """
    displayMessageAsHtml(message)
}

def displayMessageAsHtml(message) {
    def html = """
        <!DOCTYPE html>
        <html>
            <head>
            </head>
            <body>
                <div>
                    ${message}
                </div>
            </body>
        </html>
    """
    render contentType: 'text/html', data: html
}


//////////////////////////////////////////////////////////////
/////////Children Content Must be Edited for DTH//////////////
//////////////////////////////////////////////////////////////

def pollChildren(){
		log.info "starting pollChildren"
		refreshAuthToken()
		atomicState.devicedetails = [:]
        def deviceids = atomicState.deviceids
		settings.devices.each {dev ->
            def deviceid = deviceids[dev]
            def locationid = devicelocations[dev]
            def d = getChildDevice(dev)
            def Params = [
                uri: "http://developer-apis.awair.is",
                path: "v1/users/self/devices/${deviceType}/${deviceId}/air-data/5-min-avg",
                headers: ['Authorization': "Bearer ${atomicState.authToken}"],
                query: [
                    apikey: APIKey(),
                    
                ],
            ]
            
            log.debug "starting httpGet with Params = ${Params}"
            httpGet(Params) { resp ->
            try{
            	def devicedetails = atomicState.devicedetails
                devicedetails[dev] = resp.data
                atomicState.devicedetails = devicedetails
                
                def humid = resp.data.currentSensorReadings.humidity
                def temp = resp.data.
                def co2 = resp.data.
                def offline = resp.data.isDeviceOffline
                def voc = resp.data.
                def dust = resp.data.
                def pm25 = resp.data.
                def pm10 = resp.data.
                if (settings.DisplayTempInF) {temp = convertCtoF(temp)}
                def events = [
                	['humidity': humidity],
                    ['temperature': temp],
                    ['carbonDioxide': co2],
                    ['DeviceStatus': offline == true ? "offline" : "online"],
                    ['volatileOrganicCompounds': voc],
                    ['particulateMassFineDust': pm25],
                    ['particulateMassCoarseDust': pm10],
                	]
                log.info "Sending events: ${events}"
                events.each {event -> d.generateEvent(event)}
                log.debug "device data for ${deviceid} = ${devicedetails[dev]}"
                }
                catch (e)
                {
                	log.error "Error while processing events for pollChildren: ${e}"
				}
            }
    }
}

def convertCtoF(tempC) {
	float tempF = Math.round((tempC * 1.8) + 32)
	return String.format("%.1f", tempF)
}
