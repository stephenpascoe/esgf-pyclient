"""
Interface to the ESGF SAML Attribute Service.

"""

from jinja2 import Template
import uuid
import datetime
import urllib2
from xml.etree import ElementTree as ET

from pyesgf.security import NS

import logging
log = logging.getLogger(__name__)

ATS_REQUEST_TMPL = Template('''<?xml version="1.0" encoding="UTF-8"?>
<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/">
  <soap11:Body>
     <samlp:AttributeQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                           ID="{{ msg_id }}" 
                           IssueInstant="{{timestamp}}" Version="2.0">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">{{ issuer }}</saml:Issuer>
        <saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
           <saml:NameID Format="urn:esg:openid">{{ openid }}</saml:NameID>
        </saml:Subject>
        {% for attr in attributes -%}
        <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        Name="{{ attr }}"
                        NameFormat="http://www.w3.org/2001/XMLSchema#string"/>
        {% endfor -%}
     </samlp:AttributeQuery>
  </soap11:Body>
</soap11:Envelope>
''')



AZS_REQUEST_TMPL = Template('''<?xml version="1.0" encoding="UTF-8"?>
<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/">
  <soap11:Body>
    <samlp:AuthzDecisionQuery xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              ID="{{ msg_id }}" IssueInstant="{{ timestamp }}" 
                              Resource="{{ resource }}" Version="2.0">
      <saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:NameID Format="urn:esg:openid">{{ subject }}</saml:NameID>
      </saml:Subject>
      <saml:Action xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{{ action }}</saml:Action>
    </samlp:AuthzDecisionQuery>
  </soap11:Body>
</soap11:Envelope>
''')

class SAMLService(object):
    ISSUER = 'esgf-pyclient'
    REQUEST_TMPL = NotImplemented
    RESPONSE_MAKER = NotImplemented

    def __init__(self, url):
        self.url = url

    def build_request(self, **params):
        now = datetime.datetime.utcnow()
        msg_id=uuid.uuid1()
        
        return self.REQUEST_TMPL.render(
            msg_id=msg_id,
            timestamp=now.isoformat()+'Z',
            issuer=self.ISSUER,
            **params)

    def send_request(self, **params):
        post_body = self.build_request(**params)
        req = urllib2.Request(self.url, post_body)
        req.add_header('Content-Type', 'text/xml')
        req.add_header('Content-Length', str(len(req.get_data())))
        log.debug(req.headers)
        log.debug(req.get_data())
        resp = urllib2.urlopen(req)

        return self.RESPONSE_MAKER(resp)


class SAMLResponse(object):
    def __init__(self, source):
        self.xml = ET.parse(source)

    def get_subject(self):
        #!FIXME: fails if UnknownPrinicple!
        fpath = './/{{{0}}}Subject/{{{0}}}NameID'.format(NS['saml'])
        subject_el = self.xml.find(fpath)

        return subject_el.text

    def get_status(self):
        fpath = './/{{{0}}}Status/{{{0}}}StatusCode'.format(NS['saml2p'])
        sc = self.xml.find(fpath)
        
        return sc.get('Value')


class AttributeServiceResponse(SAMLResponse):
    def get_attributes(self):
        d = {}
        fpath = './/{{{0}}}AttributeStatement/{{{0}}}Attribute'.format(NS['saml'])

        for el in self.xml.findall(fpath):
            attr_name = el.get('Name')
            val_el = el.find('./{{{0}}}AttributeValue'.format(NS['saml']))
            attr_value = val_el.text

            d.setdefault(attr_name, []).append(attr_value)

        # Remove list wrapper from single-valued attributes
        for key in d:
            if len(d[key]) == 1:
                d[key] = d[key][0]

        return d



class AttributeService(SAMLService):
    REQUEST_TMPL = ATS_REQUEST_TMPL
    RESPONSE_MAKER = AttributeServiceResponse

