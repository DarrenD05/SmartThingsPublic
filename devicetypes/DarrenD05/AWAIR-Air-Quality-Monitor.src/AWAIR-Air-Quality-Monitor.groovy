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
metadata {
	definition (name: "AWAIR Air Quality Monitor", namespace: "DarrenD05", author: "Darren Donnelly") {
		capability "Temperature Measurement"
		capability "Sensor"
        capability "Relative Humidity Measurement"

		attribute "co2", "number"
		attribute "voc", "number"
		attribute "dust", "number"
        attribute "pm25", "number"
        attribute "pm10", "number"
		attribute "lastUpdated", "String"
	}

  
	tiles(scale: 2) {
		multiAttributeTile(name: "temperature", type: "generic", width: 6, height: 4, canChangeIcon: true) {
			tileAttribute("device.temperature", key: "PRIMARY_CONTROL") {
				attributeState("temperature", label: '${currentValue}°', unit:"F", defaultState: true, 
						backgroundColors: [
                                // Celsius
                                [value: 0, color: "#153591"],
                                [value: 7, color: "#1e9cbb"],
                                [value: 15, color: "#90d2a7"],
                                [value: 23, color: "#44b621"],
                                [value: 28, color: "#f1d801"],
                                [value: 35, color: "#d04e00"],
                                [value: 37, color: "#bc2323"],
                                // Fahrenheit
                                [value: 32, color: "#153591"],
                                [value: 44, color: "#1e9cbb"],
                                [value: 59, color: "#90d2a7"],
                                [value: 74, color: "#44b621"],
                                [value: 84, color: "#f1d801"],
                                [value: 95, color: "#d04e00"],
                                [value: 96, color: "#bc2323"]
						])
			}

			tileAttribute("device.humidity", key: "SECONDARY_CONTROL") {
				attributeState "humidity", label:'${currentValue}%', icon:"st.Weather.weather12"
            }
        }
		valueTile("co2", "device.co2",  width: 2, height: 2,decoration: "flat") {
			state "default", label:'${currentValue} co2 ppm'
		}
		valueTile("voc", "device.voc",  width: 2, height: 2,decoration: "flat") {
			state "default", label:'${currentValue}% voc ppm'
		}
		valueTile("dust", "device.dust",  width: 2, height: 2,decoration: "flat") {
			state "default", label:'${currentValue}% dust ppm'
		}
 		valueTile("lastUpdated", "device.lastUpdated", inactiveLabel: false, decoration: "flat", width: 6, height: 2) {
    			state "default", label:'Last Updated ${currentValue}', backgroundColor:"#ffffff"
		}
        
        main(["temperature"])
		details(["temperature", "humidity", "co2", "voc", "dust" ,"lastUpdated"])
	}


simulator {
		// TODO: define status and reply messages here
	}
}

void installed() {
    // The device refreshes every 1 minutes by default so if we miss 3 refreshes we can consider it offline
    sendEvent(name: "checkInterval", value: 60 * 3, data: [protocol: "cloud"], displayed: false)
}

// parse events into attributes
def parse(String description) {
	log.debug "Parsing '${description}'"
}

def refresh() {
	log.debug "refresh called"
	poll()
}

void poll() {
	log.debug "Executing 'poll' using parent SmartApp"
	parent.pollChildren()

}

def generateEvent(Map results) {
  results.each { name, value ->
    sendEvent(name: name, value: value)
  }
  return null
}
