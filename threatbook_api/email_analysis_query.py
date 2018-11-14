# -*- coding:utf-8 -*-
import json
import requests


class Email(object):
    """Get a list of domain names registered by an email.
    
     Attributes:
        :param apikey:With the Private API, you need the corresponding apikey. 
            It is different from the Public API apikey registered through 
            the Analysis Platform website. As our business customer or 
            partner, we will deliver your corresponding apikey by mail.
    """

    def __init__(self, api_key):
        self.api_key = api_key
        self.msg = ""
        self.data = {}
        self.response_code = -4

    def get_email(self, email):
        """
        :param email: The email address to be queried.
        :return: Returns a json object containing the total number 
            of domain and each domain name.
        """
        url = "https://x.threatbook.cn/api/v1/domain4email/query"
        parameters = {"apikey": self.api_key, "email": email}
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

