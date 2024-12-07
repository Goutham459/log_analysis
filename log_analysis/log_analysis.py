import re
import csv
from collections import defaultdict

# file paths
log_file = "sample.log"
output_csv = "log_analysis_results.csv"


FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parses the log file and extracts relevant details."""
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regex for log parsing
    log_pattern = re.compile(
        r'(?P<ip>[\d\.]+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>.*?) HTTP/\d\.\d" (?P<status>\d+) .*'
    )
    
    with open(file_path, "r") as f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                ip = match.group("ip")
                endpoint = match.group("endpoint")
                status = int(match.group("status"))

                # Count requests 
                ip_requests[ip] += 1
                endpoint_requests[endpoint] += 1

                # Count failed login 
                if status == 401:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def analyze_requests_per_ip(ip_requests):
    sorted_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    return sorted_requests

def analyze_most_accessed_endpoint(endpoint_requests):
    most_accessed = max(endpoint_requests.items(), key=lambda x: x[1])
    return most_accessed

def detect_suspicious(failed_logins):
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_to_csv(ip_analysis, most_accessed, suspicious_activity, output_file):
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP 
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_analysis)

        # Most accessed endpoint 
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed)

        # Suspicious activity 
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity.items())

def main():
    # Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file)

    # Analyze data
    ip_analysis = analyze_requests_per_ip(ip_requests)
    most_accessed = analyze_most_accessed_endpoint(endpoint_requests)
    suspicious_activity = detect_suspicious(failed_logins)

    #  Display results
    print("Requests per IP Address:")
    for ip, count in ip_analysis:
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")

    # Save results
    save_to_csv(ip_analysis, most_accessed, suspicious_activity, output_csv)
    print(f"\nResults saved to {output_csv}")

if __name__ == "__main__":
    main()
