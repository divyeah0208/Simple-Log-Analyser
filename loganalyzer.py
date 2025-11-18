from collections import Counter
import re

def analyze_log(file_path):
    total_lines = 0
    failed_logins = 0
    ip_list = []

    # Regex pattern to extract IPv4 addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            total_lines += 1

            # Count failed login attempts (customize keywords as needed)
            if "failed" in line.lower() or "authentication failure" in line.lower():
                failed_logins += 1

            # Extract IPs
            match = ip_pattern.search(line)
            if match:
                ip_list.append(match.group())

    unique_ips = set(ip_list)
    top_5_ips = Counter(ip_list).most_common(5)

    return {
        "total_lines": total_lines,
        "failed_logins": failed_logins,
        "unique_ips_count": len(unique_ips),
        "unique_ips": unique_ips,
        "top_5_ips": top_5_ips
    }


# ------------------------------
# Example usage
# ------------------------------
if __name__ == "__main__":
    log_file = input("Enter log file path: ")
    result = analyze_log(log_file)

    print("\n--- Log Analysis Report ---")
    print(f"Total lines: {result['total_lines']}")
    print(f"Failed logins: {result['failed_logins']}")
    print(f"Unique IPs: {result['unique_ips_count']}")
    print("\nTop 5 repeated IPs:")
    for ip, count in result["top_5_ips"]:
        print(f"{ip}: {count} times")
