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


# MEC Platform Management Controllers
from mm3_nfv.controllers.app_lcm_controller import AppLcmController


from mm3_nfv.databases.database_base import DatabaseBase
from mm3_nfv.databases.dbmongo import MongoDb
from typing import Type
import cherrypy
from mm3_nfv.utils import check_port
from mm3_nfv.models import *
import json
import os

@json_out(cls=NestedEncoder)
def main(database: Type[DatabaseBase]):

    #############################################
    # MEC Platform Management interfaces (mm3_nfv) #
    #############################################
    mepm_dispatcher = cherrypy.dispatch.RoutesDispatcher()

    mepm_dispatcher.connect(
        name="Provide configuration information in AppD to the MEPM-V, intended to configure the MEP to run the application instance.",
        action="configurePlatformForApp",
        controller=AppLcmController,
        route="/app_instances/:appInstanceId/configure_platform_for_app",
        conditions=dict(mecthod=["POST"]),
    )

    mepm_dispatcher.connect(
        name="Update MEC App instance Status",
        action="operateApp",
        controller=AppLcmController,
        route="/app_instances/:appInstanceId/operate",
        conditions=dict(method=["POST"]),
    )

    mepm_dispatcher.connect(
        name="Terminte MEC App instance",
        action="terminateApp",
        controller=AppLcmController,
        route="/app_instances/:appInstanceId/terminate",
        conditions=dict(method=["POST"]),
    )

    mepm_dispatcher.connect(
        name="Instantiate MEC App instance",
        action="instantiateApp",
        controller=AppLcmController,
        route="/app_instances/:appInstanceId/instantiate",
        conditions=dict(method=["POST"]),
    )

    mepm_dispatcher.connect(
        name="Get configuration of MEC App instance",
        action="mecApp_config_get",
        controller=AppLcmController,
        route="/applications/:appInstanceId/configuration",
        conditions=dict(method=["GET"]),
    )

    mepm_dispatcher.connect(
        name="Query all LCM Operations",
        action="lcmOpp_get_all",
        controller=AppLcmController,
        route="/app_lcm_op_occs",
        conditions=dict(method=["GET"]),
    )

    mepm_dispatcher.connect(
        name="Query LCM Operation",
        action="lcmOpp_get",
        controller=AppLcmController,
        route="/app_lcm_op_occs/:appLcmOpOccId",
        conditions=dict(method=["GET"]),
    )

    mepm_dispatcher.connect(
        name="Post MEC App Dns Rule",
        action="dns_rule_post_with_dns_rule_id",
        controller=AppLcmController,
        route="/applications/:appInstanceId/dns_rule/:dnsRuleId",
        conditions=dict(method=["POST"]),
    )

    mepm_dispatcher.connect(
        name="Post MEC App Dns Rules",
        action="dns_rules_post",
        controller=AppLcmController,
        route="/applications/:appInstanceId/dns_rules/",
        conditions=dict(method=["POST"]),
    )

    mepm_dispatcher.connect(
        name="Post MEC App Traffic Rule",
        action="traffic_rule_post_with_traffic_rule_id",
        controller=AppLcmController,
        route="/applications/:appInstanceId/traffic_rule/:trafficRuleId",
        conditions=dict(method=["POST"]),
    )

    mepm_dispatcher.connect(
        name="Post MEC App Traffic Rules",
        action="traffic_rules_post",
        controller=AppLcmController,
        route="/applications/:appInstanceId/traffic_rules/",
        conditions=dict(method=["POST"]),
    )

    ############################################################################

    cherrypy.config.update(
        {"server.socket_host": "0.0.0.0", "server.socket_port": 8085}
    )

    # MEPM config (mm3_nfv - extra mm3_nfv)
    mecpm_conf = {"/": {"request.dispatch": mepm_dispatcher}}
    cherrypy.tree.mount(None, "/mec_platform_mgmt/v1", config=mecpm_conf)


    # Config 404 and 403 landing pages
    cherrypy.config.update({'error_page.404': error_page_404})
    cherrypy.config.update({'error_page.403': error_page_403})
    cherrypy.config.update({'error_page.400': error_page_400})


    ######################################
    # Database Connection to all threads #
    ######################################
    if isinstance (database, DatabaseBase):
        cherrypy.engine.subscribe('start_thread', database.connect)
        cherrypy.engine.start()
    else:
        cherrypy.log("Invalid database provided to MEPM. Shutting down.")


def error_page_404(status, message, traceback, version):
    error_msg = "URI %s cannot be mapped to a valid resource." % cherrypy.request.path_info
    error = NotFound(error_msg)
    cherrypy.response.headers["Content-Type"] = "application/problem+json"
    return json.dumps(error.message().to_json())

def error_page_403(status, message, traceback, version):
    error_msg = "The operation is not allowed given the current status of the resource."
    error = Forbidden(error_msg)
    cherrypy.response.headers['Content-Type'] = "application/problem+json"
    return json.dumps(error.message().to_json())

def error_page_400(status, message, traceback, version):
    error_msg = "The operation is not allowed given the current status of the resource."
    error = BadRequest(error_msg)
    cherrypy.response.headers['Content-Type'] = "application/problem+json"
    return json.dumps(error.message().to_json())


if __name__ == "__main__":
    mongodb_addr = os.environ.get("ME_CONFIG_MONGODB_SERVER")
    mongodb_port = os.environ.get("ME_CONFIG_MONGODB_PORT")
    mongodb_username = os.environ.get("ME_CONFIG_MONGODB_ADMINUSERNAME")
    mongodb_password = os.environ.get("ME_CONFIG_MONGODB_ADMINPASSWORD")
    mongodb_database = os.environ.get("ME_CONFIG_MONGODB_DATABASE")

    database = MongoDb(mongodb_addr, mongodb_port, mongodb_username, mongodb_password, mongodb_database)
    
    oauth_addr = os.environ.get("OAUTH_SERVER")
    oauth_port = os.environ.get("OAUTH_PORT")
    oauthServer = OAuthServer(oauth_addr, oauth_port)
    cherrypy.config.update({"oauth_server": oauthServer})

    dns_api_addr = os.environ.get("DNS_API_SERVER")
    dns_api_port = os.environ.get("DNS_API_PORT")
    dnsApiServer = DnsApiServer(dns_api_addr, dns_api_port)
    cherrypy.config.update({"dns_api_server": dnsApiServer})
    
    main(database)
