import Evtx.Evtx as evtx
import re

def parse_file(filename, label):
    print(f"\n{'='*60}")
    print(f"FILE: {filename}")
    print(f"TECHNIQUE: {label}")
    print('='*60)

    with evtx.Evtx(filename) as log:
        count = 0
        for record in log.records():
            xml = record.xml()
            eid_match = re.search(r'<EventID.*?>(\d+)</EventID>', xml)
            eid = eid_match.group(1) if eid_match else "unknown"

            # grab every Data field generically, whatever its name is
            fields = re.findall(r'<Data Name="(.*?)">(.*?)</Data>', xml)

            if eid != "unknown":
                count += 1
                print(f"\nRecord #{count}")
                print(f"  Event ID: {eid}")
                for name, value in fields:
                    if value.strip():
                        print(f"  {name}: {value}")

            if count >= 3:
                break

    print(f"\nTotal records shown: {count}")


files = [
    ("sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx", "Credential Access - LSASS Memory Dump (T1003.001)"),
    ("evasion_persis_hidden_run_keyvalue_sysmon_13.evtx", "Persistence - Hidden Registry Run Key (T1547.001)"),
    ("Sysmon_UACME_33.evtx", "Privilege Escalation - UAC Bypass (T1548.002)")
]

for filename, label in files:
    try:
        parse_file(filename, label)
    except Exception as e:
        print(f"Error parsing {filename}: {e}")
