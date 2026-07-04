import Evtx.Evtx as evtx
import re

def get_fields(xml):
    eid_match = re.search(r'<EventID.*?>(\d+)</EventID>', xml)
    eid = eid_match.group(1) if eid_match else None
    fields = dict(re.findall(r'<Data Name="(.*?)">(.*?)</Data>', xml))
    return eid, fields

def detect_lsass_dump(filename):
    print("\n[Credential Access - T1003.001] LSASS Memory Access")
    with evtx.Evtx(filename) as log:
        for record in log.records():
            eid, f = get_fields(record.xml())
            if eid == "10" and f.get("TargetImage", "").lower().endswith("lsass.exe"):
                access = f.get("GrantedAccess", "")
                source = f.get("SourceImage", "unknown")
                print(f"  MATCH: process '{source}' accessed lsass.exe with rights {access}")
                print(f"  Why suspicious: non-system processes rarely need this level of access to lsass.exe")

def detect_run_key_persistence(filename):
    print("\n[Persistence - T1547.001] Registry Run Key Modification")
    with evtx.Evtx(filename) as log:
        for record in log.records():
            eid, f = get_fields(record.xml())
            if eid == "13" and "\\Run\\" in f.get("TargetObject", ""):
                image = f.get("Image", "unknown")
                target = f.get("TargetObject", "")
                details = f.get("Details", "")
                print(f"  MATCH: process '{image}' wrote to '{target}'")
                print(f"  Payload set to run at login: {details}")

def detect_uac_bypass(filename):
    print("\n[Privilege Escalation - T1548.002] UAC Bypass via DelegateExecute")
    with evtx.Evtx(filename) as log:
        for record in log.records():
            eid, f = get_fields(record.xml())
            if eid == "13" and "DelegateExecute" in f.get("TargetObject", ""):
                image = f.get("Image", "unknown")
                target = f.get("TargetObject", "")
                print(f"  MATCH: process '{image}' modified '{target}'")
            if eid == "13" and f.get("TargetObject", "").endswith("(Default)") and "ms-settings" in f.get("TargetObject", ""):
                details = f.get("Details", "")
                print(f"  Payload command set: {details}")


detect_lsass_dump("sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx")
detect_run_key_persistence("evasion_persis_hidden_run_keyvalue_sysmon_13.evtx")
detect_uac_bypass("Sysmon_UACME_33.evtx")
