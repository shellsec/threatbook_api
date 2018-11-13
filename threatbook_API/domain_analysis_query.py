# -*- coding:utf-8 -*-
import json

import requests


class DomainAnalysis(object):
    """Full information for obtaining domain analysis
    
    Obtain the IP address corresponding to the domain name, the geographical
    location information related to the IP address, the current Whois information,
    the threat type, the related attack gang or security event information, and 
    provide other more detailed intelligence data according to the customer"s needs.
    
    Attributes:
        :param apikey:With the Private API, you need the corresponding apikey. 
            It is different from the Public API apikey registered through 
            the Analysis Platform website. As our business customer or 
            partner, we will deliver your corresponding apikey by mail.
        :param domain:A string domain to be queried.
        
    """

    def __init__(self, api_key):
        self.api_key = api_key
        self.msg = ""
        self.data = {}
        self.response_code = -4

    def get_all(self, domain):
        """Get all the information about the domain.
        
        :field history_whoises：The historical WHOIS information of the domain.
               It is a JSON array, and each item is a JSON object.
               Whois: is a JSON object with the following fields:
                registrar_name,name_server,registrant_name,registrant_email,registrant_company,
                registrant_address,registrant_phone,cdate,udate,edate,alexa.
        :field cur_whois:The current WHOIS information of the domain.
                It is a JSON array, and each item is a JSON object.Same field as above.
        :field history_ips:The ip information parsed in the history of this domain.
                It is a JSON array, and each item is a JSON object.
        :field cur_ips:The ip information parsed in the current of this domain.
                It is a JSON array, and each item is a JSON object.
        :field tags:Related attack gang or security event information, json array, 
                for example: DarkHotel.
        :field judgments:The types of threats analyzed from threat intelligence, such as 
                remote control, malware, etc., is a JSON array.
        :field intelligences:Threat Intelligence, is a json array.
        :field samples:Related sample, is a json array.
        :filed domains_4_email:The domain registration mailbox and is also registered as 
                another domain name, is an array.
        :field sub_domains: The subdomain under the second-level domain corresponding to the domain,
                is an array.
                
        :return:Return data in json format.
        """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "history_whoises,cur_whois,history_ips,cur_ips,tags,judgments,"
                               "intelligences,samples,domains_4_email,sub_domains"}
        # The fields to be queried, separated by commas, with the same field name
        # as the field name in the output parameter.
        fields = ["history_whoises", "cur_whois", "history_ips", "cur_ips", "tags", "judgments",
                  "intelligences", "samples", "domains_4_email", "sub_domains"]
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                for item in fields:
                    if item not in ret_json:
                        ret_json[item] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_history_whoises(self, domain):
        """Get the history_whoises information of the domain.
        
        :field:history_whoises：The historical WHOIS information of the domain.
               It is a JSON array, and each item is a JSON object.
               Whois: is a JSON object with the following fields:
                registrar_name,name_server,registrant_name,registrant_email,registrant_company,
                registrant_address,registrant_phone,cdate,udate,edate,alexa.
        :return:Return data in json format.
        """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "history_whoises"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "history_whoises" not in ret_json:
                    ret_json["history_whoises"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_cur_whois(self, domain):
        """Get the cur_whois information of the domain.
        
        :param domain: A string domain to be queried.
        :field:cur_whois：The current WHOIS information of the domain.
                It is a JSON array, and each item is a JSON object.
               Whois: is a JSON object with the following fields:
                registrar_name,name_server,registrant_name,registrant_email,registrant_company,
                registrant_address,registrant_phone,cdate,udate,edate,alexa.
        :return: Return data in json format.
        """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "cur_whois"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "cur_whois" not in ret_json:
                    ret_json["cur_whois"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_history_ips(self, domain):
        """Get the history_ips information of the domain.
        
        :field history_ips:The ip information parsed in the history of this domain.
                It is a JSON array, and each item is a JSON object.
        :return:Return data in json format.
        """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "history_ips"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "history_ips" not in ret_json:
                    ret_json["history_ips"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_cur_ips(self, domain):
        """Get the cur_ips information of the domain.

        :field cur_ips:The ip information parsed in the current of this domain.
                It is a JSON array, and each item is a JSON object.
        :return:Return data in json format.
        """

        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "cur_ips"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "cur_ips" not in ret_json:
                    ret_json["cur_ips"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_tags(self, domain):
        """Get the tags information of the domain.

        :field tags:Related attack gang or security event information, json array, 
                for example: DarkHotel.
        :return:Return data in json format.
        """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "tags"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "tags" not in ret_json:
                    ret_json["tags"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_judgments(self, domain):
        """Get the judgments information of the domain.
        
        :field judgments:The types of threats analyzed from threat intelligence, such as 
                remote control, malware, etc., is a JSON array.
        :return: Return data in json format.
        """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "judgments"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "judgments" not in ret_json:
                    ret_json["judgments"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_intelligences(self, domain):
        """Get the intelligences information of the domain.

        :field intelligences:Threat Intelligence, is a json array.
        :return: Return data in json format.
        """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "intelligences"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "intelligences" not in ret_json:
                    ret_json["intelligences"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_samples(self, domain):
        """Get the samples information of the domain.

       :field samples:Related sample, is a json array.
       :return: Return data in json format.
       """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "samples"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "samples" not in ret_json:
                    ret_json["samples"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_domain_4_email(self, domain):
        """Get the domains_4_email information of the domain.

        :filed domains_4_email:The domain registration mailbox and is also registered as 
                another domain name, is an array.
        :return: Return data in json format.
       """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "domains_4_email"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "domains_4_email" not in ret_json:
                    ret_json["domains_4_email"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_sub_domains(self, domain):
        """Get the sub_domains information of the domain.

        :field sub_domains: The subdomain under the second-level domain corresponding to the domain,
                is an array.
        :return: Return data in json format.
       """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": "sub_domains"}
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if "sub_domains" not in ret_json:
                    ret_json["sub_domains"] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)


    def get_fields(self,domain,fields):
        """Get information about the specified field.
        :param fields:The field name of the data to be returned, the string format. 
            If there are multiple fields, the fields are separated by commas.
            The fields are as follows:
                history_whoises：The historical WHOIS information of the domain.
                    It is a JSON array, and each item is a JSON object.Whois: is a JSON 
                    object with the following fields:
                        registrar_name,name_server,registrant_name,registrant_email,registrant_company,
                        registrant_address,registrant_phone,cdate,udate,edate,alexa.
                cur_whois:The current WHOIS information of the domain.
                        It is a JSON array, and each item is a JSON object.Same field as above.
                history_ips:The ip information parsed in the history of this domain.
                        It is a JSON array, and each item is a JSON object.
                cur_ips:The ip information parsed in the current of this domain.
                        It is a JSON array, and each item is a JSON object.
                tags:Related attack gang or security event information, json array, 
                        for example: DarkHotel.
                judgments:The types of threats analyzed from threat intelligence, such as 
                        remote control, malware, etc., is a JSON array.
                intelligences:Threat Intelligence, is a json array.
                samples:Related sample, is a json array.
                domains_4_email:The domain registration mailbox and is also registered as 
                        another domain name, is an array.
                sub_domains: The subdomain under the second-level domain corresponding to the domain,
                        is an array.
        """
        url = "https://x.threatbook.cn/api/v1/domain/query"
        parameters = {"domain": domain, "apikey": self.api_key,
                      "field": fields}
        field_list = fields.split(',')
        try:
            response = requests.post(url, parameters)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                for item in field_list:
                    if item not in ret_json:
                        ret_json[item] = ""
                return ret_json
            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)


