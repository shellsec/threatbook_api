# -*- coding:utf-8 -*-
import json

import requests

class IpAnalysis(object):
    """Obtain the IP address related geographical location information, bound domain information, threat type,
    related attack gang or security event information.
    
    Attributes:
        :param apikey:With the Private API, you need the corresponding apikey. 
            It is different from the Public API apikey registered through 
            the Analysis Platform website. As our business customer or 
            partner, we will deliver your corresponding apikey by mail.
        :param ip:The ip to be queried.
        
    """

    def __init__(self, api_key):
        self.api_key = api_key
        self.msg = ""
        self.data = {}
        self.response_code = -4
        self.url = "https://x.threatbook.cn/api/v1/ip/query"

    def get_all(self, ip):
        """Get all the information related to the IP address.
        :fields: The fields to be queried, separated by commas, with the same field name as the field 
            name in the output parameter.The fields are as follows:
            Ip: A JSON object containing IP, carrier, location.
            tags:Related attack gang or security event information, json array, for example: DarkHotel.
            judgments:The types of threats analyzed from threat intelligence, such as remote control, 
                malware, etc., are a json array.
            intelligences:Threat Intelligence is a json array.
            samples:The relevant sample is a json array.
            cur_domains:The domain currently pointing to this ip is a json array.
            history_domain:The historical domain name of the IP reverse is a json map, the key is the date, 
                the value is an array, and each item is a domain.
            port:The relevant port information is a json array.
        
        """
        url = self.url
        fields = "ip,tags,judgments,intelligences,samples,cur_domains,history_domains,port"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["ip", "tags", "judgments", "intelligences", "samples", "cur_domains", "history_domains",
                               "port"]
                if ret_json["response_code"] == 0:
                    data2 = []
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    data1 = ret_json.get("port", {})
                    for item in data1:
                        if item["detail"]:
                            item["detail"] = item.get("detail").replace("\x00", "").replace("\n", ",")
                        data2.append(item)
                    ret_json["port"] = data2
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_ip(self, ip):
        """Get IP information related to the IP address."""

        url = self.url
        fields = "ip"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["ip"]
                if ret_json["response_code"] == 0:
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_tags(self, ip):
        """Get tags information related to the IP address."""
        url = self.url
        fields = "tags"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["tags"]
                if ret_json["response_code"] == 0:
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_judgments(self, ip):
        """Get judgments information related to the IP address."""
        url = self.url
        fields = "judgments"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["judgments"]
                if ret_json["response_code"] == 0:
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_intelligences(self, ip):
        """Get intelligences information related to the IP address."""
        url = self.url
        fields = "intelligences"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["intelligences"]
                if ret_json["response_code"] == 0:
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_samples(self, ip):
        """Get samples information related to the IP address."""
        url = self.url
        fields = "samples"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["samples"]
                if ret_json["response_code"] == 0:
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_cur_domains(self, ip):
        """Get cur_domains information related to the IP address."""
        url = self.url
        fields = "cur_domains"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["cur_domains"]
                if ret_json["response_code"] == 0:
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_history_domains(self, ip):
        """Get history_domains information related to the IP address."""
        url = self.url
        fields = "history_domains"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["history_domains"]
                if ret_json["response_code"] == 0:
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_port(self, ip):
        """Get port information related to the IP address."""
        url = self.url
        fields = "port"
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                fields_list = ["port"]
                if ret_json["response_code"] == 0:
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = {}
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_fields(self,ip,fields):
        """Get information about the specified field.
        :param fields:The field name of the data to be returned, the string format. 
            If there are multiple fields, the fields are separated by commas.
            The fields are as follows:
                Ip: A JSON object containing IP, carrier, location.
                tags:Related attack gang or security event information, json array, for example: DarkHotel.
                judgments:The types of threats analyzed from threat intelligence, such as remote control, 
                    malware, etc., are a json array.
                intelligences:Threat Intelligence is a json array.
                samples:The relevant sample is a json array.
                cur_domains:The domain currently pointing to this ip is a json array.
                history_domain:The historical domain name of the IP reverse is a json map, the key is the date, 
                    the value is an array, and each item is a domain.
                port:The relevant port information is a json array.
        """
        url = self.url
        parameters = {"apikey": self.api_key, "ip": ip, "field": fields}
        fields_list = fields.split(',')
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if ret_json["response_code"] == 0:
                    data2 = []
                    for item in fields_list:
                        if item not in ret_json:
                            ret_json[item] = ""
                    if "port" in fields_list:
                        data1 = ret_json.get("port", {})
                        for item in data1:
                            if item["detail"]:
                                item["detail"] = item.get("detail").replace("\x00", "").replace("\n", ",")
                            data2.append(item)
                        ret_json["port"] = data2
                    return ret_json
                else:
                    return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)
