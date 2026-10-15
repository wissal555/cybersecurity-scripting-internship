# Log Analyzer (Bash)

## Objective
Analyze Linux log files from the command line: count errors, warnings
and critical messages, and detect SSH brute-force attempts in auth.log
(MITRE ATT&CK T1110).

## Features
- Counts `error`, `warning` and `critical` lines in any log file
- Counts a custom keyword given by the user
- SSH mode: failed attempts, top 5 source IPs, targeted users,
  successful logins, alert for IPs above a threshold
- Input checks (arguments, file exists, file readable) and help option `-h`

## Requirements
- Linux (tested on Ubuntu), Bash
- Standard tools: grep, awk, sed, sort, uniq, wc
- `sudo` may be needed to read some logs (e.g. /var/log/auth.log)

## How to Run
```bash
chmod +x tool.sh
./tool.sh -h
./tool.sh <log_file> [keyword | ssh]
```

## Example Usage
```bash
./tool.sh /var/log/syslog
./tool.sh /var/log/syslog error
sudo ./tool.sh /var/log/auth.log ssh
./tool.sh test_auth.log ssh
```

## Example Output
(paste your real output here + screenshots)
![SSH analysis](screenshots/ssh_analysis.png)

## Challenges Faced
- Order of the checks (help, number of arguments, file, then analysis)
- Handling both "Failed password for root" and "for invalid user admin"
- Permissions: some logs need sudo

## Future Improvements
- Export the report to a file (-o option)
- Option parsing with getopts
- Support for web server logs (Apache/Nginx)
- Colored output and multiple files
