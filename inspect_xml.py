import Evtx.Evtx as evtx

with evtx.Evtx("sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx") as log:
    for record in log.records():
        print(record.xml())
        break
