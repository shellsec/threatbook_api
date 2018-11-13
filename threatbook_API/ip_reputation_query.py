# -*- coding:utf-8 -*-
import json
import requests


class IpReputation(object):
    """Obtain real-time IP information and image information, and obtain basic IP attribute information, such as
        IDC host, dynamic IP, downtime, VPN, proxy IP, and so on.
     
     Attributes:
        :param apikey:With the Private API, you need the corresponding apikey. 
            It is different from the Public API apikey registered through 
            the Analysis Platform website. As our business customer or 
            partner, we will deliver your corresponding apikey by mail.
        :param ip:The IP to be queried can be multiple, separated by commas, up to 10.
     """

    def __init__(self, api_key):
        self.api_key = api_key
        self.msg = ""
        self.data = {}
        self.response_code = -4
        self.url = "https://x.threatbook.cn/api/v2/ip_reputation"

    def get_all(self, ip):
        """Get current and outdated intelligence information for the IP."""
        url = self.url
        parameters = {"apikey": self.api_key, "ip": ip}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_now(self, ip):
        """Get the current valid information of the IP."""
        url = self.url
        parameters = {"apikey": self.api_key, "ip": ip}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                data1 = ret_json.get("data", {})
                for i in data1:
                    data_now = data1[i].get("now", {})
                    self.data[i] = data_now
                res = {"data": self.data, "msg": self.msg, "response_code": 0}
                return json.dumps(res)

            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_expired(self, ip):
        """Get expired intelligence information of the IP."""
        url = self.url
        parameters = {"apikey": self.api_key, "ip": ip}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                data1 = ret_json.get("data", {})
                for i in data1:
                    data_now = data1[i].get("expired", {})
                    self.data[i] = data_now
                res = {"data": self.data, "msg": self.msg, "response_code": 0}
                return json.dumps(res)

            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

