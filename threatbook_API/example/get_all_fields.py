# -*- coding:utf-8 -*-
from threatbook_API.domain_analysis_query import DomainAnalysis

# If you need to get all fields, you can need the get_all method in the module.

# create an instance object
test = DomainAnalysis('your private api_key')

# Get  all information of the domain
info = test.get_all('domain to be queried ',)
print(info)