# -*- coding:utf-8 -*-
import json
import requests
import os


class Upload(object):
    """Upload the file for analysis.
    """

    def __init__(self, api_key, sandbox_type="win7_sp1_enx86_office2013", run_time=60, file_path=os.path.abspath(".")):
        """
        :param api_key: You will need to register for a threatbook account 
            and view your API Key through the Personal Center. This Key will 
            be used for all your API operations.
        :param sandbox_type: Sandbox operating environment, available environment:
            Windows (win7_sp1_enx86 _office2013,
                    Win7_sp1_enx86_office2010,
                    Win7_sp1_enx86_office2007,
                    Win7_sp1_enx86_office2003,
                    Win7_sp1_enx64_office2013);
            Linux (ubuntu_1704_x64, centos_7_x64).
            The default is win7_sp1_enx86_office2013.
        :param run_time: Sandbox running time, default 60s, controlled within
            300s according to demand.
        :param file_path: The path where you uploaded the file.The default is the current path.
        """

        self.api_key = api_key
        self.sandbox_type = sandbox_type
        self.run_time = run_time
        self.path = file_path

    def upload_file(self, file, ):
        """
        :param file: Files that need to be analyzed, the single file size 
        is controlled within 20MB.
        :return: Returns the sha256 of the file and the URL of the report.
        """
        url = "https://s.threatbook.cn/api/v2/file/upload"
        fields = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "run_time": self.run_time
        }
        dir = self.path
        file_name = file
        files = {
            "file": (file_name, open(os.path.join(dir, file_name), "rb"))
        }
        response = requests.post(url, data=fields, files=files)
        return response.json()


class Report(object):
    """Get all or part of the report.
    Attributes:
        :param api_key: You will need to register for a threatbook account 
            and view your API Key through the Personal Center. This Key will 
            be used for all your API operations.
        :param sandbox_type: Sandbox operating environment, available environment:
            Windows (win7_sp1_enx86 _office2013,
                    Win7_sp1_enx86_office2010,
                    Win7_sp1_enx86_office2007,
                    Win7_sp1_enx86_office2003,
                    Win7_sp1_enx64_office2013);
            Linux (ubuntu_1704_x64, centos_7_x64).
            The default is win7_sp1_enx86_office2013.
        :param run_time: Sandbox running time, default 60s, controlled within
            300s according to demand.
        :param sha256:The sha256 value of the file.
    """

    def __init__(self, api_key, sandbox_type="win7_sp1_enx86_office2013", run_time=60):
        self.api_key = api_key
        self.sandbox_type = sandbox_type
        self.run_time = run_time
        self.msg = ""
        self.data = {}
        self.response_code = -4

    def get_report(self, sha256):
        """Get a full report of the file."""
        url = "https://s.threatbook.cn/api/v2/file/report"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_summary(self, sha256):
        """Get the summary information of the report"""
        url = "https://s.threatbook.cn/api/v2/file/report/summary"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_ioc(self, sha256):
        """Get threat information for documents IOC report."""
        url = "https://s.threatbook.cn/api/v2/file/report/ioc"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_system(self, sha256):
        """Get an intelligence system test report for the file."""
        url = "https://s.threatbook.cn/api/v2/file/report/system"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_network(self, sha256):
        """Get a web behavior report for the file."""
        url = "https://s.threatbook.cn/api/v2/file/report/network"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_signature(self, sha256):
        """Get the behavior signature report of the file."""
        url = "https://s.threatbook.cn/api/v2/file/report/signature"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_static(self, sha256):
        """Get a static report of the file."""
        url = "https://s.threatbook.cn/api/v2/file/report/static"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_dropped(self, sha256):
        """Get the release file report for the file."""
        url = "https://s.threatbook.cn/api/v2/file/report/dropped"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_pstree(self, sha256):
        """Get the process tree report for the file."""
        url = "https://s.threatbook.cn/api/v2/file/report/pstree"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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

    def get_multiengines(self, sha256):
        """Get a multi-engine detection report for the file."""
        url = "https://s.threatbook.cn/api/v2/file/report/multiengines"
        params = {
            "apikey": self.api_key,
            "sandbox_type": self.sandbox_type,
            "sha256": sha256
        }
        try:
            response = requests.get(url, params=params)
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


    def get_fields(self,sha256,fields):
        """
        Get the data of the corresponding field according to the sha256 of the file.
        :param fields: The field name of the data to be returned, the string format. 
            If there are multiple fields, the fields are separated by commas.
        :return: Returns data in json format that satisfies the submission.
        """
        data_list = []
        func_dict = {
            'summary':self.get_report,
            'ioc':self.get_ioc,
            'system':self.get_system,
            'network':self.get_network,
            'signature':self.get_signature,
            'static':self.get_static,
            'dropped':self.get_dropped,
            'pstree':self.get_pstree,
            'multiengines':self.get_multiengines
        }
        field_list = fields.split(',')
        for field in field_list:
            if field in func_dict:
                res = func_dict[field](sha256)
                data_list.append(res.get('data',{}))

        res = {"data": data_list, "msg": self.msg, "response_code":0}
        return json.dumps(res)


class FetchFile(object):
    """Get the digital certificate information of the file.

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

    def get_all(self, resource):
        """Get the digital certificate information of the file.

        :param resource: Sample hash to be detected, SHA256 format.
        :return: Returns a json object containing the signature organization
            name and certificate chain information.
        """

        url = "https://x.threatbook.cn/api/v1/file/fetch_file_legal_ca"
        parameter = {"apikey": self.api_key, "resource": resource}
        try:
            response = requests.post(url, parameter)
        except Exception as e:
            print(e)
        else:
            if response.status_code == 200:
                ret_json = json.loads(response.text)
                if ret_json["response_code"] == 0:
                    ret_json["msg"] = "no data"
                return ret_json

            else:
                self.msg = response.status_code, "not fount"
                res = {"data": self.data, "msg": self.msg, "response_code": self.response_code}
                return json.dumps(res)

    def get_legallssuer(self, resource):
        """
        Get the name of the organization that ultimately signed the sample, and the presence of
         the field indicates that the organization is highly trusted.
        :param resource: Sample hash to be detected, SHA256 format.
        :return: Returns a string of the organization name.
        """

        data0 = self.get_all(resource)
        if data0["response_code"] == 1:
            data1 = data0.get("LegalIssuer", {})
            res = {"LegalIssuer": data1, "msg": self.msg, "response_code": 0}
            return res
        else:
            return data0

    def get_cas(self, resource):
        """Get certificate chain information.
        :param resource: Sample hash to be detected, SHA256 format.
        :return: Returns a list of the details of the certificate chain.
        """

        data0 = self.get_all(resource)
        if data0["response_code"] == 1:
            data1 = data0.get("cas", {})
            res = {"cas": data1, "msg": self.msg, "response_code": 0}
            return res
        else:
            return data0
