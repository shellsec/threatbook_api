# -*- coding:utf-8 -*-
from threatbook_api.domain_analysis_query import DomainAnalysis

# If you need to get some fields, you can need the get_fields method in the module.

# create an instance object
test = DomainAnalysis('your private api_key')

# Get the current whois information of the domain
fields = 'cur_whois,history_whois'
info = test.get_fields('domain to be queried ',fields)
print(info)