import psutil  #helps too see all running process
import wmi     #helps to access windows services
import datetime  #it adds time in logs

print("\n--- Windows Monitoring Agent ---\n")

# Simple logging function
def log(message):
    with open("security_log.txt", "a") as f:
        f.write(str(datetime.datetime.now()) + " - " + message + "\n")


# 1. Check Parent-Child

print("Checking parent-child processes...\n")

for p in psutil.process_iter(['pid', 'ppid', 'name']):
    try:
        parent_name = psutil.Process(p.info['ppid']).name()

        if parent_name == "winword.exe" and p.info['name'] == "powershell.exe":
            msg = "Suspicious: winword → powershell"
            print("⚠", msg)
            log(msg)

    except:
        pass

# 2. Check Unknown Processes

print("\nChecking unknown processes...\n")

safe_processes = ["explorer.exe", "svchost.exe", "lsass.exe"]

for p in psutil.process_iter(['name']):
    try:
        if p.info['name'] not in safe_processes:
            msg = "Unknown process: " + p.info['name']
            print("⚠", msg)
            log(msg)

    except:
        pass

# 3. Check Suspicious Paths

print("\nChecking suspicious locations...\n")

for p in psutil.process_iter(['name', 'exe']):
    try:
        path = str(p.info['exe']).lower()

        if "temp" in path or "appdata" in path:
            msg = "Suspicious path: " + p.info['name'] + " → " + path
            print("⚠", msg)
            log(msg)


    except:
        pass

# 4. Check Services

print("\nChecking services...\n")

c = wmi.WMI()

for s in c.Win32_Service():
    try:
        if "temp" in str(s.PathName).lower():
            msg = "Suspicious service: " + s.Name
            print("⚠", msg)
            log(msg)

    except:
        pass

# 5. Simple Report

with open("report.txt", "w") as f:
    f.write("Scan completed. Now we can see the alerts directly into security_log.txt\n")


print("\n--- Scan Finished ---\n")




# DASHBOARD 

html_data = ""

# for reading logs
try:
    with open("security_log.txt", "r") as f:
        logs = f.readlines()

    for line in logs:
        line = line.strip()

        if "Suspicious" in line or "Unknown" in line:
            html_data += f"<div style='background:#ef4444; padding:10px; margin:5px; border-radius:5px'>{line}</div>"
        else:
            html_data += f"<div style='background:#22c55e; padding:10px; margin:5px; border-radius:5px'>{line}</div>"

except:
    html_data = "<div>No logs found</div>"


# Creating dashboard

with open("dashboard.html", "w", encoding="utf-8") as f:
    f.write(f"""
<html>
<head>
    <title>Dashboard</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5">
</head>

<body style="background:#0f172a; color:white; font-family:Arial;">
<h1 style="text-align:center;"> Windows Monitoring Dashboard</h1>

{html_data}

</body>
</html>
""")
