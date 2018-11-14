# -*- coding:utf-8 -*-
# If you only need to get a field, you can use the methods in the module directly.
from threatbook_api.domain_analysis_query import DomainAnalysis

test1 = DomainAnalysis('your private api_key')

# Get the current whois information of the domain
info = test1.get_cur_whois('domain to be queried  ')
print(info)
