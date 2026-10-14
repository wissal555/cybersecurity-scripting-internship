#!/bin/bash
# =====================================================================
# Name        : log_analyzer.sh
# Author      : Wissal Ezzairi
# Description : Simple log analyzer for Linux.
#               - Mode 1: counts error / warning / critical lines
#               - Mode 2: counts a custom keyword
#               - Mode 3 ("ssh"): analyzes SSH authentication logs
#                 (auth.log) to detect brute-force signs
#                 (MITRE ATT&CK T1110 - Brute Force)
# Usage       : ./log_analyzer.sh -h
#               ./log_analyzer.sh <log_file>
#               ./log_analyzer.sh <log_file> <keyword>
#               ./log_analyzer.sh <log_file> ssh
# Examples    : ./log_analyzer.sh /var/log/syslog
#               ./log_analyzer.sh /var/log/syslog error
#               sudo ./log_analyzer.sh /var/log/auth.log ssh
# =====================================================================
 
# ---------------------------------------------------------------------
# usage : prints the help message (does not exit, the caller decides)
# ---------------------------------------------------------------------

usage(){
  echo "Usage : $0 <log_file> [keyword | ssh]"
  echo "Examples :"
  echo "  $0 /var/log/syslog           (counts error, warning, critical)"
  echo "  $0 /var/log/syslog error     (counts one keyword)"
  echo "  $0 /var/log/auth.log ssh     (SSH brute-force analysis)"
  echo "Options :"
  echo "  -h    show this help"
}
# ---------------------------------------------------------------------
# count_err : counts the lines containing a keyword (case-insensitive)
# $1 = log file, $2 = keyword
# ---------------------------------------------------------------------
count_err(){
  local path=$1
  local type=$2
  local result=$(grep -i -c "$type" "$path")
  echo "$type : $result" 
}
# ---------------------------------------------------------------------
# analyze_ssh : analyzes SSH authentication attempts
# $1 = log file (usually /var/log/auth.log)
# ---------------------------------------------------------------------
analyze_ssh(){

 local log_file=$1
 local threshold=5     # alert if an IP has more failures than this

 # 1. Total number of failed password attempts 
 local failed_passwd=$(grep -i -c "Failed password" "$log_file")
 echo "Number of failed attempts : $failed_passwd"
 
 
 # 2. Top 5 source IPs
 echo "Top 5 IP addresses :"
 grep "Failed password" "$log_file"|awk '{print $(NF-3)}'| sort | uniq -c |sort -nr | head -n 5
 
 # 3. Targeted users
  echo "Trageted users :"
  grep "Failed password" "$log_file" | sed -E 's/.*Failed password for (invalid user )?//'| awk '{print $1}' | sort | uniq -c | sort -nr
 
 # 4. Successful logins (password or public key)
 local success=$(grep -E -c "Accepted password|Accepted publickey" "$log_file")
 echo "Numbre of successful logins : $success"

 # 5. Alert: IPs with more than 5 failures   
 echo "IP Alert (more than 5 failures) :"
 grep "Failed password" "$log_file" | awk '{print $(NF-3)}'| sort | uniq -c| awk -v t="$threshold" '$1 > t {print "  [!] " $2 " : " $1 " failures"; found=1} END {if (!found) print "  none"}'
}

# ---------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------
 
# Help option (checked first: "-h" is a single argument)
if [ "$1" == "-h" ]; then
  usage
  exit 0
fi
# Check the number of arguments (1 or 2 expected)
if [ $# -eq 0 ] || [ $# -gt 2 ]; then
 echo "Error : invalid number of argument"
 usage
 exit 1
fi  
# Check that the file exists
if [ ! -f "$1" ]; then
   echo "Path '$1' not found">&2
   exit 1
fi
# Check that the file is readable
if [ ! -r "$1" ]; then
  echo "File not readable. Try with sudo">&2
  exit 1
fi
# Choose what to analyze
if [ $# -eq 1 ]; then
  count_err "$1" "error"
  count_err "$1" "warning"
  count_err "$1" "critical"
elif [ $# -eq 2 ]; then
  if [ "$2" == "ssh" ]; then
    analyze_ssh "$1"
  else 
    count_err "$1" "$2"
  fi
fi  
# Total number of lines (reading via "<" avoids printing the file name)
nbr_ligne=$(wc -l <"$1")
echo "Nombre total de logs: $nbr_ligne"

