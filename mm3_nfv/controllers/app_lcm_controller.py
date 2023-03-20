# Copyright 2022 Centro ALGORITMI - University of Minho
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

import os
import sys
import jsonschema
sys.path.append("../../")
from mm3_nfv.models import *
from hashlib import md5
import uuid
from mm3_nfv.controllers.app_callback_controller import *

from osmclient import client
from osmclient.common.exceptions import ClientException

import yaml
import copy

HEADERS = {"Content-Type": "application/json"}

MM5_PORT = cherrypy.config.get("mm5_port")
MM5_ADDRESS = cherrypy.config.get("mm5_address")
OSM_SERVER = cherrypy.config.get("osm_server")


class AppLcmController:

#######################################################################################
#                                   LCM OPERATIONS                                    #
#                        Instantiate, Operate, and Terminate                          #
#######################################################################################
    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def instantiateApp(self, appInstanceId: str):
        """
            7.4.6 Resource: instantiate application instance task
            Resource URI: {apiRoot}/app_lcm/v1/app_instances/{appInstanceId}/instantiate
            7.4.6.1 Description
            This resource represents the task of instantiating an application instance. The client can use this resource to instantiate
            an application instance.
        """
        
        cherrypy.log("Received request to instantiate app %s" %appInstanceId)

        appStatus = cherrypy.thread_data.db.query_col(
            "appStatus",
            query=dict(appInstanceId=appInstanceId),
            find_one=True,
        )

        # If app exists in db return error
        if appStatus is not None and appStatus.state.instantiationState == InstantiationState.INSTANTIATED:
            error_msg = "Application %s is already instantiated." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()

        data = cherrypy.request.json

        try:
            #TO-DO InstantiateAppRequest class
            instantiateAppRequest = InstantiateAppRequest.from_json(data)
        except (TypeError, jsonschema.exceptions.ValidationError) as e:
            error = BadRequest(e)
            return error.message()


        # MUST CHECK IF instance already exists and if it is in NOT_INSTANTIATED state, if it is the case update state
        # assuming the app does not exist in appStatus:
        appState  = AppInstanceState(InstantiationState.INSTANTIATED.value, OperationalState.STARTED.value)
        appStatusDict = dict(
            appInstanceId=appInstanceId,
            state = appState.to_json(),
            indication="STARTING"
        )

        cherrypy.thread_data.db.create("appStatus", appStatusDict)

        lifecycleOperationOccurrenceId = str(uuid.uuid4())
        lastModified = cherrypy.response.headers['Date']
    
        lcmOperationOccurence = dict(
            lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId,
            appInstanceId=appInstanceId, 
            stateEnteredTime=lastModified,
            operation="STARTING",
            operationStatus=OperationStatus.PROCESSING.name
        )

        cherrypy.thread_data.db.create("lcmOperations", lcmOperationOccurence)

        # TO-DO process to instantiate the NS
        # hostname = "192.168.86.216"
        # myclient = client.Client(host=hostname, sol005=True)
        # createNS = myclient.ns.create(nsd, nsName, accountNS)
        # TODO: errors 401, 403, 404, 406 and 429 

        cherrypy.response.status = 202
        return dict(lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId)


    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def operateApp(self, appInstanceId: str):
        """
            7.4.8 Resource: operate application instance task
            Resource URI: {apiRoot}/app_lcm/v1/app_instances/{appInstanceId}/operate
            7.4.8.1 Description
            This resource represents the task of changing the operational state of the application instance. The client can use this
            resource to start or stop an application instance.
        """
        cherrypy.log("Received request to change app %s state" %appInstanceId)

        appStatus = cherrypy.thread_data.db.query_col(
            "appStatus",
            query=dict(appInstanceId=appInstanceId),
            find_one=True,
        )

        # If app exists in db
        if appStatus is None or appStatus.state.instantiationState == InstantiationState.NOT_INSTANTIATED:
            error_msg = "Application %s not instantiated." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()

        data = cherrypy.request.json
        # The process of generating the class allows for "automatic" validation of the json and
        # for filtering after saving to the database
        try:
            # Verify the requestion body if its correct about its schema:
            updateState = OperateAppRequest.from_json(data)

        except (TypeError, jsonschema.exceptions.ValidationError) as e:
            error = BadRequest(e)
            return error.message()

        # if updateState.changeStateTo.value == appStatus["state"]["operationalState"].value:
        # AttributeError: 'str' object has no attribute 'value'
        if updateState.changeStateTo.value == appStatus["state"]["operationalState"]:
            error_msg = "Application %s already in state %s." % (appInstanceId, updateState.changeStateTo.value)
            error = Conflict(error_msg)
            return error.message()


        if updateState.changeStateTo.value == ChangeStateTo.STOPPED.value:
            operationAction = OperationActionType.STOPPING


        appState  = AppInstanceState(InstantiationState.INSTANTIATED, OperationalState.STOPPED)

        appInstanceDict = dict(appInstanceId=appInstanceId)
        appStatusDict = dict(
            indication=updateState.changeStateTo.name,
            state=appState.to_json()
        )
        cherrypy.thread_data.db.update(
            "appStatus", 
            appInstanceDict, 
            appStatusDict
        )

        lifecycleOperationOccurrenceId = str(uuid.uuid4())
        lastModified = cherrypy.response.headers['Date']

        lcmOperationOccurence = dict(
            lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId,
            appInstanceId=appInstanceId, 
            stateEnteredTime=lastModified,
            operation=operationAction,
            operationStatus=OperationStatus.PROCESSING.name
        )

        cherrypy.thread_data.db.create("lcmOperations", lcmOperationOccurence)

        # Send operate app message to MEP
        # check if there is a way to stop an NS on osmclient
       
        return dict(lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId)


    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def terminateApp(self, appInstanceId: str):
        """
            7.4.7 Resource: terminate application instance task
            Resource URI: {apiRoot}/app_lcm/v1/app_instances/{appInstanceId}/terminate
            7.4.7.1 Description
            This resource represents the task of terminating an application instance. The client can use this resource to terminate an
            application instance.
        """
        cherrypy.log("Received request to terminate app %s" %appInstanceId)

        appStatus = cherrypy.thread_data.db.query_col(
            "appStatus",
            query=dict(appInstanceId=appInstanceId),
            find_one=True,
        )

        # If app does not exists in db
        if appStatus is None:
            error_msg = "Application %s is not instantiated." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()

        data = cherrypy.request.json
        # The process of generating the class allows for "automatic" validation of the json and
        # for filtering after saving to the database
        try:
            # Verify the requestion body if its correct about its schema:
            termination = TerminateAppInstance.from_json(copy.deepcopy(data))
        except (TypeError, jsonschema.exceptions.ValidationError) as e:
            error = BadRequest(e)
            return error.message()

        if data['appInstanceId'] != appInstanceId:
            error_msg = "Application in body %s does not match the one in the URL %s." % (data['appInstanceId'], appInstanceId)
            error = BadRequest(error_msg)
            return error.message()

        # Send configuration to MEP via Mm5
        url = "http://%s:%s/mec_platform_mgmt/v1/app_instances/%s/terminate" % (MM5_ADDRESS, MM5_PORT, appInstanceId)
        mm5_response = requests.post(url, headers=HEADERS, data=json.dumps(data))

        appInstanceDict = dict(appInstanceId=appInstanceId)
        appStatusDict = dict(
            {"indication" : OperationActionType.TERMINATING.name}
        )
        
        cherrypy.thread_data.db.update(
            "appStatus",
            appInstanceDict,
            appStatusDict
        )

        lifecycleOperationOccurrenceId = str(uuid.uuid4())
        lastModified = cherrypy.response.headers['Date']

        # If operation TERMINATING fails in MEP, create LCM Operation 
        # Occurrence with state FAILED_TEMP
        if mm5_response.status_code != 200:
            lcmOperationOccurence = dict(
                lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId,
                appInstanceId=appInstanceId, 
                stateEnteredTime=lastModified,
                operation=OperationActionType.TERMINATING.name,
                operationStatus=OperationState.FAILED_TEMP.name
            )
            cherrypy.thread_data.db.create("lcmOperations", lcmOperationOccurence)
            cherrypy.response.status = mm5_response.status_code
            
            resp = mm5_response.json()
            resp["detail"] = resp["detail"] + " Created LCM Operation Occurrence with id: %s (Operation state FAILED_TEMP)." %lifecycleOperationOccurrenceId
            return resp

        # If operation TERMINATING succeeds in MEP, create LCM Operation 
        # Occurrence with state PROCESSING
        else:
            lcmOperationOccurence = dict(
                lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId,
                appInstanceId=appInstanceId, 
                stateEnteredTime=lastModified,
                operation=OperationActionType.TERMINATING.name,
                operationStatus=OperationStatus.PROCESSING.name
            )
            cherrypy.thread_data.db.create("lcmOperations", lcmOperationOccurence)

            # TO-DO Check the MEP that controls the appInstanceId
            # send a terminate request to MEP (remove configuration)
            # proceed to NS removal
            # hostname = "192.168.86.216"
            # myclient = client.Client(host=hostname, sol005=True)
            # createNS = myclient.ns.delete(nsName)
            # set application instantiationState to "NOT_INSTANTIATED"
            # TO-DO errors 401, 403, 404, 406 and 429

            # Remove App Instance from appStatus
            appInstanceDict = dict(appInstanceId=appInstanceId)
            cherrypy.thread_data.db.remove("appStatus", appInstanceDict)

            cherrypy.response.status = 201

            return dict(lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId)


    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def configurePlatformForApp(self, appInstanceId: str):
        """
            Resource URI: {apiRoot}/app_lcm/v1/app_instances/{appInstanceId}/configure_platform_for_app

            7.7.6 Resource: configure_platform_for_app task
            This resource represents the task of providing configuration information in AppD to the MEPM-V, intended to
            configure the MEP to run an application instance which is instantiated from the AppD. The configuration information
            includes the traffic rules, DNS rules, the required and optional services, and services produced by the application
            instance, etc. The client can use this resource to provide to the MEPM-V configuration information for the MEP to run
            an application instance after the corresponding VNF instance has been instantiated by NFV-MANO.
        """
        
        cherrypy.log("Received request to configure app %s" %appInstanceId)

        appStatus = cherrypy.thread_data.db.query_col(
            "appStatus",
            query=dict(appInstanceId=appInstanceId),
            find_one=True,
        )

        # If app exists in db return error
        if appStatus is not None:
            error_msg = "Application %s already configured." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()

        data = cherrypy.request.json
        data_aux = copy.deepcopy(data)
        
        try:
            configRequest = ConfigPlatformForAppRequest.from_json(data)
        except (TypeError, jsonschema.exceptions.ValidationError) as e:
            error = BadRequest(e)
            return error.message()

        # Send configuration to MEP via Mm5
        url = "http://%s:%s/mec_platform_mgmt/v1/app_instances/%s/configure_platform_for_app" % (MM5_ADDRESS, MM5_PORT, appInstanceId)
        mm5_response = requests.post(url, headers=HEADERS, data=json.dumps(data_aux))

        appState  = AppInstanceState(InstantiationState.INSTANTIATED.value, OperationalState.STARTED.value)
        appStatusDict = dict(
            appInstanceId=appInstanceId,
            state = appState.to_json(),
            indication="STARTING"
        )

        cherrypy.thread_data.db.create("appStatus", appStatusDict)

        lifecycleOperationOccurrenceId = str(uuid.uuid4())
        lastModified = cherrypy.response.headers['Date']

        
        if mm5_response.status_code != 201:
            lcmOperationOccurence = dict(
                lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId,
                appInstanceId=appInstanceId, 
                stateEnteredTime=lastModified,
                operation="STARTING",
                operationStatus=OperationState.FAILED_TEMP.name
            )

            cherrypy.thread_data.db.create("lcmOperations", lcmOperationOccurence)
            cherrypy.response.status = mm5_response.status_code

            resp = mm5_response.json()
            resp["detail"] = resp["detail"] + " Created LCM Operation Occurrence with id: %s (Operation state FAILED_TEMP)." %lifecycleOperationOccurrenceId
            return resp
    
        else:
            lcmOperationOccurence = dict(
                lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId,
                appInstanceId=appInstanceId, 
                stateEnteredTime=lastModified,
                operation="STARTING",
                operationStatus=OperationStatus.PROCESSING.name
            )

            cherrypy.thread_data.db.create("lcmOperations", lcmOperationOccurence)
            cherrypy.response.status = 201

        return dict(lifecycleOperationOccurrenceId=lifecycleOperationOccurrenceId)




    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def mecApp_update_config(self, appInstanceId: str):
        #Update App configuration
        
        cherrypy.log("Received request to reconfigure app %s" %appInstanceId)

        appStatus = cherrypy.thread_data.db.query_col(
            "appStatus",
            query=dict(appInstanceId=appInstanceId),
            find_one=True,
        )

        # If app exists in db
        if appStatus is None or appStatus['state'] == "NOT_INSTANTIATED":
            error_msg = "Application %s does not exist." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()

        data = cherrypy.request.json

        try:
            configRequest = ConfigPlatformForAppRequest.from_json(data)
        except (TypeError, jsonschema.exceptions.ValidationError) as e:
            error = BadRequest(e)
            return error.message()  

        # Configure Traffic Rules
        for ruleDescriptor in configRequest.appTrafficRule:

            rule = ruleDescriptor.trafficRule
                
            CallbackController.execute_callback(
                args=[appInstanceId, rule],
                func=CallbackController._configureTrafficRule,
                sleep_time=0
            )

            cherrypy.thread_data.db.create(
                "trafficRules",
                object_to_mongodb_dict(
                rule,
                extra=dict(appInstanceId=appInstanceId)
                )
            )
        
        # Configure DNS Rules
        for ruleDescriptor in configRequest.appDNSRule:

            rule = ruleDescriptor.dnsRule
                
            CallbackController.execute_callback(
                args=[appInstanceId, rule],
                func=CallbackController._configureDnsRule,
                sleep_time=0
            )

            lastModified = cherrypy.response.headers['Date']

            new_rec = {
                "appInstanceId": appInstanceId, 
                "lastModified": lastModified,
                } | rule.to_json()
            cherrypy.thread_data.db.create("dnsRules", new_rec)

        cherrypy.response.status = 204
        return None


    # TODO: CHECK IF THIS IS CORRECT
    # INCOMPLETE
    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def mecApp_config_get(self, appInstanceId: str):
        #Get App configuration
        
        cherrypy.log("Received request to get app %s configuration" %appInstanceId)

        appStatus = cherrypy.thread_data.db.query_col(
            "appStatus",
            query=dict(appInstanceId=appInstanceId),
            find_one=True,
        )

        # If app exists in db
        if appStatus is None or appStatus['state'] == "NOT_INSTANTIATED":
            error_msg = "Application %s does not exist." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()

        # Get Traffic Rules
        traffic_rules = cherrypy.thread_data.db.query_col(
            "trafficRules",
            query=dict(appInstanceId=appInstanceId)
        )

        traffic_rules = [TrafficRuleDescriptor(trafficRule=TrafficRule.from_json(rule)) for rule in traffic_rules]

        # Get DNS Rules
        dns_rules = cherrypy.thread_data.db.query_col(
            "dnsRules",
            query=dict(appInstanceId=appInstanceId)
        )

        dns_rules = [DNSRuleDescriptor(dnsRule=DNSRule.from_json(rule)) for rule in dns_rules]

        return ConfigPlatformForAppResponse(appTrafficRule=traffic_rules, appDNSRule=dns_rules)


    @json_out(cls=NestedEncoder)
    def lcmOpp_get(self, **kwargs):
        """
        Get the status of all LCM operations
        """
        
        if kwargs != {}:
            error_msg = "Invalid attribute(s): %s" % (str(kwargs))
            error = BadRequest(error_msg)
            return error.message()

        result = list(cherrypy.thread_data.db.query_col("lcmOperations", query={}))
        
        return result


    @json_out(cls=NestedEncoder)
    def lcmOpp_get_with_lcmoppId(self, appLcmOpOccId:str, **kwargs):
        """
        Get the status of a LCM operation
        """

        if kwargs != {}:
            error_msg = "Invalid attribute(s): %s" % (str(kwargs))
            error = BadRequest(error_msg)
            return error.message()

        query = dict(
            lifecycleOperationOccurrenceId=appLcmOpOccId
        )
        result = cherrypy.thread_data.db.query_col(
            "lcmOperations", query=query, find_one=True
        )
        if result is None:
            error = NotFound("No LCM operation found with the given id")
            return error.message()
        return result


    @json_out(cls=NestedEncoder)
    def osmclient_tests(self, appInstanceId: str):
        cherrypy.log("Request to test osmclient received")
        hostname = "192.168.86.210"
        myclient = client.Client(host=hostname, sol005=True)
        resp = myclient.nsd.list()
        print(yaml.safe_dump(resp, indent=4, default_flow_style=False))

        return resp

