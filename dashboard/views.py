from django.shortcuts import render

def home(request):
    mitre_events = [
        {"event": "Failed SSH Login", "technique": "T1110", "name": "Brute Force", "severity": "Medium"},
        {"event": "PowerShell Execution", "technique": "T1059", "name": "Command and Scripting Interpreter", "severity": "High"},
        {"event": "Suspicious Admin Login", "technique": "T1078", "name": "Valid Accounts", "severity": "High"},
        {"event": "Port Scanning Activity", "technique": "T1046", "name": "Network Service Discovery", "severity": "Medium"},
        {"event": "Credential Dumping Attempt", "technique": "T1003", "name": "OS Credential Dumping", "severity": "High"},
        {"event": "Malicious Script Execution", "technique": "T1059", "name": "Command and Scripting Interpreter", "severity": "High"},
        {"event": "Remote Service Access", "technique": "T1021", "name": "Remote Services", "severity": "Medium"},
        {"event": "Suspicious File Download", "technique": "T1105", "name": "Ingress Tool Transfer", "severity": "Medium"},
        {"event": "Persistence via Startup Folder", "technique": "T1547", "name": "Boot or Logon Autostart Execution", "severity": "High"},
        {"event": "Encoded PowerShell Command", "technique": "T1027", "name": "Obfuscated Files or Information", "severity": "High"},
        {"event": "Unusual Login Time", "technique": "T9991", "name": "Example Low 1", "severity": "Low"},
        {"event": "Access to Non-Critical File", "technique": "T9992", "name": "Example Low 2", "severity": "Low"}
    ]


    counts = {"High": 0, "Medium": 0, "Low": 0}
    for e in mitre_events:
        counts[e["severity"]] += 1

    return render(request, 'dashboard/home.html', {
        'events': mitre_events,
        'high_count': counts["High"],
        'medium_count': counts["Medium"],
        'low_count': counts["Low"]
    })