# -*- coding:utf-8 -*-
import json

import  requests


class Ioc(object):
    """
    Check whether the domain or IP has threat information such as C2.
     Attributes:
        :param apikey:With the Private API, you need the corresponding apikey. 
            It is different from the Public API apikey registered through 
            the Analysis Platform website. As our business customer or 
            partner, we will deliver your corresponding apikey by mail.
        :param q:The IP or domain to be queried.
    """

    def __init__(self,api_key):
        self.api_key = api_key
        self.msg = ""
        self.data = {}
        self.response_code = -4

    def get_ioc(self,q):
        """Query the threat intelligence information of the domain.
        :param q: The domain to be queried.
        """
        url = "https://x.threatbook.cn/api/v1/dns"
        parameters = {"apikey": self.api_key, "q": q}
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
