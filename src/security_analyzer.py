from pathlib import Path
from collections import Counter
import sys

def parse_log_line(line):
    parts = line.strip().split()

    timestamp = parts[0] + " " + parts[1]
    event = parts[2]
    username = parts[3].split("=")[1]
    ip = parts[4].split("=")[1]

    return timestamp, event, username, ip

def get_severity(risk_score):
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 30:
        return "MEDIUM"
    else:
        return "LOW"

def detect_bruteforce(count):
    if count >= 10:
        return 80
    elif count >= 8:
        return 70
    elif count >= 5:
        return 60
    return 0

def detect_success_after_failure(count):
    if count > 0:
        return 80
    return 0

def detect_password_spraying(user_count):
    if user_count >= 7:
        return 60
    elif user_count >= 5:
        return 50
    elif user_count >= 3:
        return 40
    return 0

log_file = Path("sample.log")

print("Security Log Analyzer")
print(f"Reading log file: {log_file}")

try:
    with open(log_file, "r") as file:
        for line in file:
            print(line.strip())
except FileNotFoundError:
    print(f"ERROR: Log file not found: {log_file}")
    sys.exit(1)

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
    risk_score = detect_bruteforce(count)

    if risk_score > 0:
        severity = get_severity(risk_score)
        print(
            f"{severity}: Possible brute-force attack from {ip} "
            f"with {count} failed attempts "
            f"(risk score: {risk_score})"
        )


print("\nParsed events:")

with open(log_file, "r") as file:
    for line in file:
        timestamp, event, username, ip = parse_log_line(line)
        print(timestamp, event, username, ip)
print("\nSuccessful logins after failed attempts:")

failed_before_success = {}
successful_after_failure = {}

with open(log_file, "r") as file:
    for line in file:
        timestamp, event, username, ip = parse_log_line(line)

        if event == "LOGIN_FAILED":
            failed_before_success[ip] = failed_before_success.get(ip, 0) + 1

        elif event == "LOGIN_SUCCESS" and ip in failed_before_success:
           risk_score = detect_success_after_failure(
               failed_before_success[ip]
           )

           successful_after_failure[ip] = failed_before_success[ip]

           if risk_score > 0:
               severity = get_severity(risk_score)
               print(
                   f"{severity}: {ip} had "
                   f"{failed_before_success[ip]} failed attempts "
                   f"before a successful login "
                   f"(risk score: {risk_score})"
                ) 
                        

print("\nPossible password spraying:")

users_by_ip = {}

with open(log_file, "r") as file:
    for line in file:
        timestamp, event, username, ip = parse_log_line(line)

        if event == "LOGIN_FAILED":
            if ip not in users_by_ip:
                users_by_ip[ip] = set()

            users_by_ip[ip].add(username)

for ip, users in users_by_ip.items():
    if len(users) >= 3:
        risk_score = detect_password_spraying(len(users))

        severity = get_severity(risk_score)
        print(
            f"{severity}: Possible password spraying from {ip} "
            f"targeting {len(users)} users "
            f"(risk score: {risk_score})"
        )

print("\nGenerating security report...")

report_file = Path("reports/security_report.txt")

with open(report_file, "w") as report:
    report.write("Security Log Analyzer Report\n")
    report.write("===========================\n\n")

    report.write(f"Total failed login attempts: {failed_logins}\n\n")

    report.write("Failed login attempts by IP:\n")
    for ip, count in ip_counts.items():
        report.write(f"{ip}: {count}\n")

    report.write("\nBrute-force detections:\n")
    for ip, count in ip_counts.items():
        risk_score = detect_bruteforce(count)

        if risk_score > 0:
            severity = get_severity(risk_score)
            report.write(
                f"{severity}: Possible brute-force attack from {ip} "
                f"with {count} failed attempts "
                f"(risk score: {risk_score})\n"
            )

    report.write("\nSuccessful logins after failed attempts:\n")

    for ip, count in successful_after_failure.items():
        risk_score = detect_success_after_failure(count)

        if risk_score > 0:
            severity = get_severity(risk_score)
            report.write(
                f"{severity}: {ip} had {count} failed attempts "
                f"before a successful login "
                f"(risk score: {risk_score})\n"
            )

    report.write("\nPassword spraying detections:\n")

    for ip, users in users_by_ip.items():
        if len(users) >= 3:
            risk_score = detect_password_spraying(len(users))
            severity = get_severity(risk_score)

            report.write(
                f"{severity}: Possible password spraying from {ip} "
                f"targeting {len(users)} users "
                f"(risk score: {risk_score})\n"
            )

print(f"Report saved to: {report_file}")