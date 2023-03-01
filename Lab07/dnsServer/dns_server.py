'''DNS Server for Content Delivery Network (CDN)
'''

from cmath import sqrt
from random import random
import sys
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math

import re
from collections import namedtuple


__all__ = ["DNSServer", "DNSHandler"]


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = []
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        with open(dns_file) as fp:
            lines = fp.readlines()
            for line in lines:
                tmp = line.split()
                if tmp != []:
                    self._dns_table.append(tmp)

    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        for item in self.table:
            print(item)
        super().__init__(request, client_address, server)

    def calc_distance(self, pointA, pointB):
        ''' TODO: calculate distance between two points '''
        return math.sqrt((pointA[0] - pointB[0])**2 + (pointA[1] - pointB[1])**2)

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address
        # Find matched item in DNS Table
        target_item = None
        # Compare each item and deal with point at end
        for item in self.table:
            tmp1 = item[0].split('.')
            if tmp1[-1] == '':
                tmp1.pop()
            tmp2 = request_domain_name.split('.')
            if tmp2[-1] == '':
                tmp2.pop()
            if len(tmp1) == len(tmp2):
                flag = True
                for i in range(len(tmp1)):
                    if tmp1[i] != '*' and tmp1[i] != tmp2[i]:
                        flag = False
                        break
                if flag:
                    target_item = item
        # If no matched item, return (None, None)
        if target_item == None:
            return (response_type, response_val)
        # If item type is CNAME, then return it
        if target_item[1] == "CNAME":
            response_type = target_item[1]
            response_val = target_item[2]
        # If item type it A, then...
        elif target_item[1] == "A":
            response_type = target_item[1]
            # if only one items, return it
            if len(target_item) == 3:
                response_val = target_item[2]
            # if have more than one item, return the nearest
            else:
                client_local = IP_Utils.getIpLocation(client_ip)
                # if can't find client, then random return
                if client_local == None:
                    response_val = target_item[random.randint(2, len(target_item))]
                # if can find client, then return the nearest
                else:
                    min_dist = self.calc_distance(client_local, IP_Utils.getIpLocation(target_item[2]))
                    response_val = target_item[2]
                    for item in target_item[2:]:
                        dist_tmp = self.calc_distance(client_local, IP_Utils.getIpLocation(item))
                        if dist_tmp < min_dist:
                            min_dist = dist_tmp
                            response_val = item
        # -------------------------------------------------
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
