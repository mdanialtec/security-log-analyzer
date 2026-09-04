from pathlib import Path
from collections import Counter

def parse_log_line(line):
    parts = line.strip().split()

    timestamp = parts[0] + " " + parts[1]
    event = parts[2]
    username = parts[3].split("=")[1]
    ip = parts[4].split("=")[1]

    return timestamp, event, username, ip

log_file = Path("sample.log")

print("Security Log Analyzer")
print(f"Reading log file: {log_file}")

with open(log_file, "r") as file:
    for line in file:
        print(line.strip())

failed_logins = 0
failed_ips = []

with open(log_file, "r") as file:
    for line in file:
        if "LOGIN_FAILED" in line:
            failed_logins += 1
            ip = line.split("ip=")[1].strip()
            failed_ips.append(ip)

print(f"Failed login attempts: {failed_logins}")

ip_counts = Counter(failed_ips)

print("Failed login attempts by IP:")
for ip, count in ip_counts.items():
    print(f"{ip}: {count}")

print("\nSuspicious IPs:")

for ip, count in ip_counts.items():
    if count >= 5:
        print(f"WARNING: Possible brute-force attack from {ip}")

print("\nParsed events:")

with open(log_file, "r") as file:
    for line in file:
        timestamp, event, username, ip = parse_log_line(line)
        print(timestamp, event, username, ip)
print("\nSuccessful logins after failed attempts:")

failed_before_success = {}

with open(log_file, "r") as file:
    for line in file:
        timestamp, event, username, ip = parse_log_line(line)

        if event == "LOGIN_FAILED":
            failed_before_success[ip] = failed_before_success.get(ip, 0) + 1

        elif event == "LOGIN_SUCCESS" and ip in failed_before_success:
            if failed_before_success[ip] > 0:
                print(
                    f"ALERT: {ip} had "
                    f"{failed_before_success[ip]} failed attempts "
                    f"before a successful login"
                )        