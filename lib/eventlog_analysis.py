import win32evtlog
import win32evtlogutil
import win32security
import win32con
import datetime

def get_event_logs(log_type):
    server = 'localhost'
    log_type = log_type
    hand = win32evtlog.OpenEventLog(server, log_type)
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    return events

def parse_event(event):
    event_dict = {}
    event_dict['EventID'] = event.EventID
    event_dict['TimeGenerated'] = event.TimeGenerated.Format()
    event_dict['SourceName'] = event.SourceName
    event_dict['EventType'] = event.EventType
    event_dict['EventCategory'] = event.EventCategory
    event_dict['EventData'] = event.StringInserts
    return event_dict

def analyze_event_logs(log_type):
    events = get_event_logs(log_type)
    parsed_events = [parse_event(event) for event in events]
    return parsed_events

def analyze_sysmon_logs():
    return analyze_event_logs('Microsoft-Windows-Sysmon/Operational')

def analyze_windows_defender_logs():
    return analyze_event_logs('Microsoft-Windows-Windows Defender/Operational')

def analyze_applocker_logs():
    return analyze_event_logs('Microsoft-Windows-AppLocker/EXE and DLL')

def analyze_powershell_logs():
    return analyze_event_logs('Microsoft-Windows-PowerShell/Operational')
