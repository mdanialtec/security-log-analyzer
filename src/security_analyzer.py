from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta
import sys

BRUTE_FORCE_WINDOW_MINUTES = 5

BRUTE_FORCE_HIGH_THRESHOLD = 5
BRUTE_FORCE_HIGH_RISK_THRESHOLD = 8
BRUTE_FORCE_CRITICAL_THRESHOLD = 10

PASSWORD_SPRAYING_MEDIUM_THRESHOLD = 3
PASSWORD_SPRAYING_HIGH_RISK_THRESHOLD = 5
PASSWORD_SPRAYING_HIGH_THRESHOLD = 7

def parse_log_line(line):
    parts = line.strip().split()

    if len(parts) != 5:
        return None

    try:
        timestamp = parts[0] + " " + parts[1]
        event = parts[2]
        username = parts[3].split("=", 1)[1]
        ip = parts[4].split("=", 1)[1]

        if not username or not ip:
            return None

        datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        return timestamp, event, username, ip

    except (IndexError, ValueError):
        return None

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
    if count >= BRUTE_FORCE_CRITICAL_THRESHOLD:
        return 80
    elif count >= BRUTE_FORCE_HIGH_RISK_THRESHOLD:
        return 70
    elif count >= BRUTE_FORCE_HIGH_THRESHOLD:
        return 60
    return 0

def detect_bruteforce_window(timestamps):
    timestamps = sorted(timestamps)

    if len(timestamps) < 5:
        return 0

    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

    for i in range(len(timestamps)):
        start_time = timestamps[i]
        count = 1

        for j in range(i + 1, len(timestamps)):
            if timestamps[j] - start_time <= window:
                count += 1
            else:
                break

        risk_score = detect_bruteforce(count)

        if risk_score > 0:
            return risk_score

    return 0

def detect_success_after_failure(count):
    if count > 0:
        return 80
    return 0

def detect_password_spraying(user_count):
    if user_count >= PASSWORD_SPRAYING_HIGH_THRESHOLD:
        return 60
    elif user_count >= PASSWORD_SPRAYING_HIGH_RISK_THRESHOLD:
        return 50
    elif user_count >= PASSWORD_SPRAYING_MEDIUM_THRESHOLD:
        return 40
    return 0

def main():
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
    failed_timestamps_by_ip = {}
    malformed_logs = 0

    with open(log_file, "r") as file:
        for line in file:
            result = parse_log_line(line)

            if result is None:
                malformed_logs += 1
                continue

            timestamp, event, username, ip = result

            if event == "LOGIN_FAILED":
                failed_logins += 1

                failed_ips.append(ip)

                if ip not in failed_timestamps_by_ip:
                    failed_timestamps_by_ip[ip] = []

                parsed_time = datetime.strptime(
                    timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )

                failed_timestamps_by_ip[ip].append(parsed_time)
    print(f"Failed login attempts: {failed_logins}")
    print(f"Malformed log entries: {malformed_logs}")

    ip_counts = Counter(failed_ips)

    print("Failed login attempts by IP:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")

    print("\nSuspicious IPs:")

    for ip, timestamps in failed_timestamps_by_ip.items():
        risk_score = detect_bruteforce_window(timestamps)

        if risk_score > 0:
            severity = get_severity(risk_score)
            print(
                f"{severity}: Possible brute-force attack from {ip} "
                f"within {BRUTE_FORCE_WINDOW_MINUTES} minutes "
                f"(risk score: {risk_score})"
            )


    print("\nParsed events:")

    with open(log_file, "r") as file:
        for line in file:
            result = parse_log_line(line)

            if result is None:
                print(f"Malformed log entry skipped: {line.strip()}")
                continue

            timestamp, event, username, ip = result
            print(timestamp, event, username, ip)
    print("\nSuccessful logins after failed attempts:")

    failed_before_success = {}
    successful_after_failure = {}

    with open(log_file, "r") as file:
        for line in file:
            result = parse_log_line(line)

            if result is None:
                continue

            timestamp, event, username, ip = result

            if event == "LOGIN_FAILED":
                failed_before_success[ip] = failed_before_success.get(ip, 0) + 1

            elif event == "LOGIN_SUCCESS" and ip in failed_before_success:
                risk_score = detect_success_after_failure(
                    failed_before_success[ip]
                )

                successful_after_failure[ip] = failed_before_success[ip]
                del failed_before_success[ip]

                if risk_score > 0:
                    severity = get_severity(risk_score)
                    print(
                        f"{severity}: {ip} had "
                        f"{successful_after_failure[ip]} failed attempts "
                        f"before a successful login "
                        f"(risk score: {risk_score})"
                    ) 
                            

    print("\nPossible password spraying:")

    users_by_ip = {}

    with open(log_file, "r") as file:
        for line in file:
            result = parse_log_line(line)

            if result is None:
                continue

            timestamp, event, username, ip = result

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
        report.write(f"Malformed log entries: {malformed_logs}\n\n")

        report.write("Failed login attempts by IP:\n")
        for ip, count in ip_counts.items():
            report.write(f"{ip}: {count}\n")

        report.write("\nBrute-force detections:\n")
        for ip, timestamps in failed_timestamps_by_ip.items():
            risk_score = detect_bruteforce_window(timestamps)

            if risk_score > 0:
                severity = get_severity(risk_score)
                report.write(
                    f"{severity}: Possible brute-force attack from {ip} "
                    f"within {BRUTE_FORCE_WINDOW_MINUTES} minutes "
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

if __name__ == "__main__":
    main()
