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
from osmclient import common
from osmclient.common.exceptions import ClientException, OsmHttpException
from osmclient.common.exceptions import NotFound as OsmNotFound

import copy
import yaml
from jinja2 import Environment, FileSystemLoader
import subprocess as sp
import magic
import re

HEADERS = {"Content-Type": "application/json"}

class AppLcmController:
#######################################################################################
#                                   LCM OPERATIONS                                    #
#                        Instantiate, Operate, and Terminate                          #
#######################################################################################
    
    # TODO:  errors 406 and 429
    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def instantiateApp(self, appInstanceId: str):
        """
            7.4.6 Resource: instantiate application instance task
            Resource URI: {apiRoot}/app_lcm/v1/app_instances/{appInstanceId}/instantiate
            7.4.6.1 Description
            This resource represents the task of instantiating an application instance. 
            The client can use this resource to instantiate an application instance.
        """
        
        cherrypy.log("Received request to instantiate app %s" %appInstanceId)

        """
        # CREDENTIALS
        try:
            oauth = cherrypy.config.get("oauth_server")
            credentials = oauth.register()
            token = oauth.get_token(credentials["client_id"], credentials["client_secret"])
            credentials["access_token"] = token
            secret = dict(access_token=base64.b64encode(token.encode('ascii')).decode('ascii'))
        except:
            error_msg = "OAuth server is not available, please try again in a few minutes."
            error = Unauthorized(error_msg)
            return error.message()
         """

        appStatus = cherrypy.thread_data.db.query_col(
            "appStatus",
            query=dict(appInstanceId=appInstanceId),
            find_one=True,
        )

        # If app exists and is not in NOT_INSTANTIATED state or READY, return error
        # MUST CHECK IF instance already exists and if it is in NOT_INSTANTIATED state, if it is the case update state
        # assuming the app does not exist in appStatus:
        if appStatus is not None:
            if appStatus['state']['instantiationState'] != InstantiationState.NOT_INSTANTIATED.value:
                error_msg = "Application %s is already instantiated." % (appInstanceId)
                error = Conflict(error_msg)
                return error.message()
            
            elif appStatus['indication'] != IndicationType.READY.value:
                error_msg = "Application %s is not ready to be instantiated." % (appInstanceId)
                error = Forbidden(error_msg)
                return error.message()
            

        data = cherrypy.request.json

        try:
            instantiateNsRequest = InstantiateNsRequest.from_json(data)

        except (TypeError, jsonschema.exceptions.ValidationError) as e:
            error = BadRequest(e)
            return error.message()

        # Process to instantiate the NS
        osm_server = cherrypy.config.get("osm_server")
        osmclient = client.Client(host=osm_server, sol005=True)
        
        try:
            # (nsr_name <=> ns_name), (account <=> vim account)
            ns_id = osmclient.ns.create(nsd_name=data['nsdId'], nsr_name=data['nsName'], account=data['vimAccountId'])

        except ClientException as e:
            print("ClientException:", str(e))
            print(f"class {e.__class__}")
        
            # <class 'osmclient.common.exceptions.NotFound'>
            error = NotFound(str(e))
            return error.message()


        # Look for ip and port linked to vimAccountId
        try:
            # search for the vim account in the k8s clusters
            k8s_clusters = osmclient.k8scluster.list()
            for cluster in k8s_clusters:
                cluster_info = osmclient.k8scluster.get(cluster['name'])
                if cluster_info['vim_account'] == data['vimAccountId']:
                    url = cluster_info["credentials"]["clusters"][0]["cluster"]["server"]
                    match = re.match(r"https?://([\d.]+):(\d+)", url)
                    ip_address = match.group(1)
                    #port = int(match.group(2))
                    break
        except Exception as e:
            error = BadRequest(e)
            return error.message()


        appState  = AppInstanceState(InstantiationState.INSTANTIATED.value, OperationalState.STARTED.value)
        appStatusDict = dict(
            appInstanceId = appInstanceId,
            state = appState.to_json(),
            indication = "STARTING",
            nsInstanceId = ns_id,
            vimAccountId = data['vimAccountId'],
            ip = ip_address,
            port = cherrypy.config.get("mm5_port"),
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
        if appStatus is None or appStatus['state']['instantiationState'] == InstantiationState.NOT_INSTANTIATED:
            error_msg = "Application %s not instantiated." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()

        data = cherrypy.request.json
        # The process of generating the class allows for "automatic" validation of the json and
        # for filtering after saving to the database
        try:
            # Verify the requestion body if its correct about its schema:
            updateState = OperateAppRequest.from_json(copy.deepcopy(data))
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
            operationAction = OperationActionType.STOPPING.name
            appState  = AppInstanceState(InstantiationState.INSTANTIATED.value, OperationalState.STOPPED.value)
        elif updateState.changeStateTo.value == ChangeStateTo.STARTED.value:
            operationAction = OperationActionType.STARTING.name
            appState  = AppInstanceState(InstantiationState.INSTANTIATED.value, OperationalState.STARTED.value)

        appInstanceDict = dict(appInstanceId=appInstanceId)
        appStatusDict = dict(
            indication=updateState.changeStateTo.name,
            state=appState.to_json()
        )


        # Send request to MEP via Mm5
        # TODO: catch errors from mep
        mm5_address = appStatus["ip"]
        mm5_port = appStatus["port"]
        
        url = "http://%s:%s/mec_platform_mgmt/v1/app_instances/%s/operate" % (mm5_address, mm5_port, appInstanceId)
        mm5_response = requests.post(url, headers=HEADERS, data=json.dumps(data))
        
        code = mm5_response.status_code
        if code == 400:
            detail = mm5_response.json()['detail']
            error = BadRequest(detail)
            return error.message()
        elif code == 409:
            detail = mm5_response.json()['detail']
            error = Conflict(detail)
            return error.message()
        elif code != 200:
            detail = mm5_response.json()['detail']
            error = Error(detail)
            return error.message()

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
        # check if there is a way to stop an NS on osmclient => only create and delete
       
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

        # Send to MEP via Mm5
        mm5_address = appStatus["ip"]
        mm5_port = appStatus["port"]
        url = "http://%s:%s/mec_platform_mgmt/v1/app_instances/%s/terminate" % (mm5_address, mm5_port, appInstanceId)
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
            # TODO: set application instantiationState to "NOT_INSTANTIATED"
            # TODO: errors 401, 403, 404, 406 and 429
            osm_server = cherrypy.config.get("osm_server")
            osmclient = client.Client(host=osm_server, sol005=True)
        
            try:
                resp = osmclient.ns.delete(appStatus['nsInstanceId'])

            except ClientException as e:
                # Handle ClientException errors here
                print("ClientException:", str(e))
                print(f"class {e.__class__}")
            
                # <class 'osmclient.common.exceptions.NotFound'>
                error = NotFound(str(e))
                return error.message()
        

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

        if appStatus is None:
            error_msg = "Application %s is not instantiated." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()


        # check if is already configured: if yes return error
        if ("configured" in appStatus) and (appStatus['configured'] == True):
            error_msg = "Application %s already configured." % (appInstanceId)
            error = Conflict(error_msg)
            return error.message()
        # check if appInstance is in INSTANTIATED state: if not return error
        elif appStatus['state']['instantiationState'] != "INSTANTIATED":
            error_msg = "Application %s is not in INSTANTIATED state." % (appInstanceId)
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
        mm5_address = appStatus["ip"]
        mm5_port = appStatus["port"]
        url = "http://%s:%s/mec_platform_mgmt/v1/app_instances/%s/configure_platform_for_app" % (mm5_address, mm5_port, appInstanceId)
        mm5_response = requests.post(url, headers=HEADERS, data=json.dumps(data_aux))

        appState  = AppInstanceState(InstantiationState.INSTANTIATED.value, OperationalState.STARTED.value)
        appStatusDict = dict(
            appInstanceId=appInstanceId,
            state = appState.to_json(),
            indication="STARTING",
            configured = True
        )

        cherrypy.thread_data.db.update("appStatus", dict(appInstanceId=appInstanceId), appStatusDict)

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

    """
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


    # TODO: Complete and test
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
    """

    @json_out(cls=NestedEncoder)
    def lcmOpp_get_all(self, **kwargs):
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
    def lcmOpp_get(self, appLcmOpOccId:str, **kwargs):
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

    
    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def create_vnfd(self):
        '''
        Uses osmclient to create knf packages with the descriptors
        '''
        cherrypy.log("Request to create packages received")
        content = cherrypy.request.json

        # Load templates file from templates folder
        path = '/home/netedge/mm3_nfv/'
        path_yaml = path+'packages/'+content['name']+"_vnfd.yaml"
        
        #----------------# KNF Descriptor #----------------#
        env = Environment(loader = FileSystemLoader(path+'templates/'), trim_blocks=True, lstrip_blocks=True)
        knf_template = env.get_template('netedge-mep_knf_based.j2')
        
        # Create a KNF descriptor by given parameters in a dictionary
        with open(path_yaml, "w") as f:
            output = f.write(knf_template.render(content))

        #----------------# Onboarding #----------------#
        osm_server = cherrypy.config.get("osm_server")
        bashCommand = 'osm --hostname '+osm_server+' vnfd-create '+path_yaml

        try:
            ob_vnfd = sp.run(
                bashCommand.split(),
                check=True, 
                capture_output=True
                )
            
            resp = ob_vnfd.stdout.decode().strip()

        except sp.CalledProcessError as e:
            # Processing error message from osmclient
            match = re.match(r'.*?(\{.*\}).*', e.output.decode(), re.DOTALL)
    
            if match:
                error = json.loads(match.group(1))
                if error['status'] == 409:
                    error_msg = error['detail']
                    error = Conflict(error_msg)
                    return error.message()
            else:
                return e.output.decode()
        
        return resp
    

    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def create_vnfd_file(self):
        '''
        Uses osmclient to create knfs with the descriptors
        '''
        cherrypy.log("Request to create VNF descriptor received")
        content = cherrypy.request.json

        path = '/home/netedge/mm3_nfv/'
        path_yaml = path+'packages/'+content['file_name']

        #----------------# Onboarding #----------------#
        osm_server = cherrypy.config.get("osm_server")
        bashCommand = 'osm --hostname '+osm_server+' vnfd-create '+path_yaml

        try:
            ob_vnfd = sp.run(
                bashCommand.split(),  
                check=True,
                capture_output=True)
           
            resp = ob_vnfd.stdout.decode().strip()

        except sp.CalledProcessError as e:
            match = re.match(r'.*?(\{.*\}).*', e.output.decode(), re.DOTALL)
            if match:
                error = json.loads(match.group(1))
                if error['status'] == 409:
                    error_msg = error['detail']
                    error = Conflict(error_msg)
                    return error.message()
            else:
                return e.output.decode()

        return resp
        

    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def create_nsd(self):
        '''
        Uses osmclient to create NSs with the descriptors
        '''
        cherrypy.log("Request to create NS descriptor received")
        content = cherrypy.request.json

        # Load templates file from templtes folder
        path = '/home/netedge/mm3_nfv/'
        path_yaml = path+'packages/'+content['name']+"_nsd.yaml"

        #----------------# NS Descriptor #----------------#
        env = Environment(loader = FileSystemLoader(path+'templates/'), trim_blocks=True, lstrip_blocks=True)
        ns_template = env.get_template('netedge-mep_ns_based.j2')

        # Create a NS descriptor by given parameters in a dictionary
        with open(path_yaml, "w") as f:
            f.write(ns_template.render(content))

        #----------------# Onboarding #----------------#
        osm_server = cherrypy.config.get("osm_server")
        bashCommand = 'osm --hostname ' + osm_server + ' nsd-create ' + path_yaml

        try:
            ob_nsd = sp.run(
                bashCommand.split(), 
                check=True,
                capture_output=True
                )
            resp = ob_nsd.stdout.decode().strip()

        except sp.CalledProcessError as e:
            match = re.match(r'.*?(\{.*\}).*', e.output.decode(), re.DOTALL)
    
            if match:
                error = json.loads(match.group(1))
                if error['status'] == 409:
                    error_msg = error['detail']
                    error = Conflict(error_msg)
                    return error.message()
            else:
                return e.output.decode()
        
        return resp


    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def create_nsd_file(self):
        '''
        Uses osmclient to create NSs with the descriptors
        '''
        cherrypy.log("Request to create NS descriptor received")
        content = cherrypy.request.json

        path = '/home/netedge/mm3_nfv/'
        path_yaml = path+'packages/'+content['file_name']

        #----------------# Onboarding #----------------#
        osm_server = cherrypy.config.get("osm_server")
        bashCommand = 'osm --hostname ' + osm_server + ' nsd-create ' + path_yaml

        try:
            ob_nsd = sp.run(
                bashCommand.split(), 
                check=True,
                capture_output=True
                )
            resp = ob_nsd.stdout.decode().strip()

        except sp.CalledProcessError as e:
            match = re.match(r'.*?(\{.*\}).*', e.output.decode(), re.DOTALL)
    
            if match:
                error = json.loads(match.group(1))
                if error['status'] == 409:
                    error_msg = error['detail']
                    error = Conflict(error_msg)
                    return error.message()
            else:
                return e.output.decode()
        
        return resp
    
    
    """
    @cherrypy.tools.json_in()
    @json_out(cls=NestedEncoder)
    def vim_mep_registration(self):
        cherrypy.log("Request to register VIM to MEP received")
        content = cherrypy.request.json

        vim_id = content['vim-account']
        ip = content['ip']
        port = content['port']

        mepReg = cherrypy.thread_data.db.query_col(
            "mepRegistration",
            query=dict(vimAccountId=vim_id),
            find_one=True,
        )

        if mepReg is None:
            # create a new entry
            cherrypy.thread_data.db.create(
                "mepRegistration",
                {"vimAccountId": vim_id, "port": port, "ip": ip},
            )
            return "Created new entry with VIM ID: " + vim_id + " IP: " + ip + " and port: " + str(port)
        else:
            # update existing entry
            cherrypy.thread_data.db.update(
                "mepRegistration",
                {"vimAccountId": vim_id},
                {"port": port, "ip": ip},
            )
            return "Updated entry with VIM ID: " + vim_id + " IP: " + ip + " and port: " + str(port)
    
    """