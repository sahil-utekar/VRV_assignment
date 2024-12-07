import re
import csv
from collections import Counter, defaultdict

#To Define threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Function to parse the log file and extract information
def parse_log_file(file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>GET|POST) (?P<endpoint>\/\S*) HTTP\/1\.1".*?(?P<status>\d{3})'
    )
    failed_login_pattern = "401"

    with open(file_path, "r") as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                ip = match.group("ip")
                endpoint = match.group("endpoint")
                status = match.group("status")

                # Count requests per IP
                ip_requests[ip] += 1

                # Count requests per endpoint
                endpoint_requests[endpoint] += 1

                # Count failed login attempts
                if status == failed_login_pattern:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

# Function to save results to CSV
def save_to_csv(file_name, ip_requests, most_accessed, suspicious_ips):
    with open(file_name, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        writer.writerow([])

        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow(most_accessed)
        writer.writerow([])

        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main function
def main():
    log_file = "sample.log"  # Replace with the actual log file name
    output_csv = "log_analysis_results.csv"

    # Parse log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file)

    # Sort IP requests by count
    sorted_ip_requests = dict(sorted(ip_requests.items(), key=lambda x: x[1], reverse=True))

    # Find the most accessed endpoint
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])

    # Detect suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display results
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests.items():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(output_csv, sorted_ip_requests, most_accessed_endpoint, suspicious_ips)
    print(f"\nResults saved to {output_csv}")

if __name__ == "__main__":
    main()