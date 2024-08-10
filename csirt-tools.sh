#!/bin/bash
# Copyright Yoga CSIRT

# Function to display the banner
display_banner() {
    clear
    cat << "EOF"


           ___________ ________  ______
          / ____/ ___//  _/ __ \/_  __/
         / /    \__ \ / // /_/ / / /
        / /___ ___/ // // _, _/ / /
        \____//____/___/_/ |_| /_/

            Incident Response Tools by: Yoga

EOF
}

# Function to display the main menu
display_menu() {
    echo -e "\033[1;34m************************************************\033[0m"
    echo -e "\033[1;34mIncident Response Tools v1.0 By: Yoga\033[0m"
    echo -e "\033[1;34m************************************************\033[0m"
    echo -e "\e[1;33m" # Yellow color
    echo "Please choose an option:"
    echo "1) Check System Version"
    echo "2) Check Process, Service and Apps"
    echo "3) Check Network Communication"
    echo "4) Check User, Crontab and History"
    echo "5) Check File Modification Search"
    echo "6) Check Writable Directory/Files/SUID"
    echo "7) Check Backdoor Files"
    echo "8) Check Access Log"
    echo "9) Check Auth Log"
    echo "10) Check System Log"
    echo "11) Exit"
    echo -e "\e[0;033m"
    read -p "Enter your choice [1-10]: " choice
}

# Function to display access log analysis menu
display_access_log_menu() {
    echo -e "\033[1;34m************************************************************\033[0m"
    echo -e "\033[1;34mAccess Log Analysis\033[0m"
    echo -e "\033[1;34m************************************************************\033[0m"
    echo "Please choose an analysis option:"
    echo "1) See which IP accesses the server the most"
    echo "2) See the activity of a specific IP"
    echo "3) See the most frequently accessed page or URL"
    echo "4) See the distribution of all status codes"
    echo "5) Search for a specific status code"
    echo "6) See what time the server is busiest"
    echo "7) See the distribution of various user-agents"
    echo "8) Search by HTTP Method"
    echo "9) Find SQL injection payload"
    echo "10) Search for XSS payload"
    echo "11) Search for LFI/RFI payload"
    echo "12) Search for Admin Page"
    echo "13) Return to Main Menu"
    read -p "Enter your choice [1-13]: " access_choice
}

# Function to display access log analysis menu
display_auth_log_menu() {
    echo -e "\033[1;34m************************************************************\033[0m"
    echo -e "\033[1;34mAuth Log Analysis\033[0m"
    echo -e "\033[1;34m************************************************************\033[0m"
    echo "Please choose an analysis option:"
    echo "1) Failed login attempts"
    echo "2) Authentication failures"
    echo "3) Successful logins"
    echo "4) Uses of sudo or su"
    echo "5) SSH key usage"
    echo "6) Login attempts from a specific IP"
    echo "7) Activity of a specific user"
    echo "8) Back to main menu"
    read -p "Enter your choice [1-8]: " access_choice
}

# Display the banner for the first time
display_banner

while true; do
    display_menu

    # Display the banner before processing the choice
    display_banner

    # Process user choice
    case $choice in
        1)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mSystem Version Information:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
            uname -a
            cat /etc/lsb-release
            echo ""
	    echo -e "\033[1;34mDisk Usage:\033[0m"
	    df -h
	    echo ""
	    lsblk
	    echo ""
	    echo -e "\033[1;34mRAM Usage:\033[0m"
	    free -mh
	    echo ""
            echo -e "\033[1;33mRecommendation: Check for known vulnerabilities or patches related to the detected system version.\033[0m"
            ;;
        2)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mProcess, Service and Apps Information:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
	    echo -e "\033[1;34mRunning all process:\033[0m"
            ps -aux
            echo ""
	    echo -e "\033[1;34mCurrent user process:\033[0m"
            ps -ef | grep -v '^root' | grep -E '/tmp|/dev/shm|nc|curl|wget|bash|sh|python|perl|php'
            echo ""
	    echo -e "\033[1;34mServices that are set to run at startup:\033[0m"
     	    systemctl list-unit-files --type=service | grep enabled
            echo ""
            echo -e "\033[1;34mStatus of running services:\033[0m"
	    systemctl list-units --type=service --state=running
            echo ""
            echo -e "\033[1;34mInstalled Packages:\033[0m"
	    dpkg -l
 	    echo ""
            echo -e "\033[1;33mRecommendation: Review running processes and startup for any suspicious activity or unknown services.\033[0m"
            ;;
        3)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mNetwork Communication Information:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;34mInbound Connections:\033[0m"
            netstat -tulnp 
            echo ""
            echo -e "\033[1;34mOutbound Connections:\033[0m"
            netstat -antup
            echo ""
            echo -e "\033[1;34mEstablished Connections:\033[0m"
            netstat -antup | grep "ESTA"
            echo ""
            echo -e "\033[1;34mFirewall:\033[0m"
            echo ""
            iptables -L -v -n
	    echo ""
            echo -e "\033[1;34mConnected Users:\033[0m"
            w
            echo ""
            echo -e "\033[1;34mDNS Configuration:\033[0m"
            cat /etc/resolv.conf
            echo ""
            echo -e "\033[1;34mHostname:\033[0m"
            cat /etc/hostname
            echo ""
            echo -e "\033[1;34mHosts File:\033[0m"
            cat /etc/hosts
            echo ""
            echo -e "\033[1;33mRecommendation: Monitor network traffic for unusual connections, and verify the legitimacy of established connections.\033[0m"
            ;;
        4)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mUser Information:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;34mUsers:\033[0m"
            cat /etc/passwd
            echo ""
            echo -e "\033[1;34mUsers with Bash:\033[0m"
            cat /etc/passwd | grep "bash"
            echo ""
            echo -e "\033[1;34mLast Logins:\033[0m"
            lastlog
            last
            echo ""
            echo -e "\033[1;34mCurrent logged-in users:\033[0m"
            w
            echo ""
            echo -e "\033[1;34mUsers with Sudo:\033[0m"
            getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | while read user; do echo "User: $user"; sudo -l -U $user; echo "--------------------------------"; done
            echo ""
            echo -e "\033[1;34mDisplay Crontab for Each User:\033[0m"
            for user in $(cut -f1 -d: /etc/passwd); do echo "Crontab for $user:"; crontab -u $user -l; echo ""; done
 	    echo ""
            echo -e "\033[1;34mDisplay bash_history for Each User:\033[0m"; 
	    for user in $(cut -f1 -d: /etc/passwd); do homedir=$(getent passwd "$user" | cut -d: -f6); bash_history_file="$homedir/.bash_history"; if [ -f "$bash_history_file" ]; then echo -e "\033[1;34mbash_history for $user:\033[0m"; nl -w3 -s'. ' "$bash_history_file"; else echo "No bash_history found for $user"; fi; echo ""; done
	    echo -e "\033[1;33mRecommendation: Validate user accounts and review login history for unauthorized access.\033[0m"
            ;;
        5)
	    default_dir=$( [ -d /var/www/html ] && echo /var/www/html || ([ -d /var/www ] && echo /var/www || ([ -d /home ] && echo /home)))
	    default_date=$(date '+%Y-%m-%d')

	    echo ""
	    echo -e "\033[1;32mPlease enter the directory path (press Enter to use default: $default_dir):\033[0m"
	    read target_dir
	    target_dir=${target_dir:-$default_dir}

	    if [ ! -d "$target_dir" ]; then
    	      echo -e "\033[1;31mError: Directory $target_dir does not exist. Please enter a valid directory.\033[0m"
    	    exit 1
	    fi

	    echo ""
	    echo -e "\033[1;32mPlease enter the date for the search in the last 30 days before (press Enter to use today's date: $default_date):\033[0m"
	    read target_date
	    target_date=${target_date:-$default_date}

	    start_date=$(date -d "$target_date -30 days" '+%Y-%m-%d')

	    echo -e ""
	    echo -e "\033[1;32m----------------------------------------\033[0m"
	    echo -e "\033[1;32mDirectory Listings: $target_dir\033[0m"
	    echo -e "\033[1;32m----------------------------------------\033[0m"
	    echo -e ""
	    ls -alrt "$target_dir"

	   echo -e ""
	   modified_files=$(find "$target_dir" -type f -newermt "$start_date" ! -newermt "$target_date" -ls)

	   if [ -z "$modified_files" ]; then
    	     echo -e "\033[1;31mNo files found modified in the last 30 days before $target_date.\033[0m"
	  else
    	    echo -e "\033[1;34mFiles Modified in the Last 30 Days Before $target_date (Recursive):\033[0m"
    	    echo "$modified_files"
	  fi

	  echo ""
	  echo -e "\033[1;33mRecommendation: Check for suspicious files or recent changes in critical directories.\033[0m"
          ;;
        6)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mDirectory/Files Writable:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo ""
            echo -e "\033[1;34mDirectory:\033[0m"
	    find / \( -path /dev -o -path /proc -o -path /sys \) -prune -o -type d -perm -o=w -exec ls -ald {} \; 2>/dev/null
	    echo ""
	    echo "Press Enter to continue (Files)..."
	    read -r  # Menunggu user menekan Enter
            echo ""
            echo -e "\033[1;34mFiles:\033[0m"
	    find / \( -path /dev -o -path /proc -o -path /sys \) -prune -o -type f -perm -o=w -exec ls -ald {} \; 2>/dev/null
	    echo ""
	    echo "Press Enter to continue (SUID)..."
	    read -r  # Menunggu user menekan Enter
	    echo ""
	    echo -e "\033[1;34mSUID:\033[0m"
	    find / -perm -u=s -type f -exec ls -al {} \; 2>/dev/null
            echo ""
            echo -e "\033[1;33mRecommendation: Check for suspicious files or recent changes in critical directories/files/SUID.\033[0m"
            ;;
 
        7)
	    default_dir="/var/www/html"

	    echo ""
	    echo -e "\033[1;32mPlease enter the directory path to search for backdoor files (press Enter to use default: $default_dir):\033[0m"
	    read target_dir
	    target_dir=${target_dir:-$default_dir}

	    if [ ! -d "$target_dir" ]; then
	    	echo -e "\033[1;31mError: Directory $target_dir does not exist. Please enter a valid directory.\033[0m"
  	    exit 1
	    fi

	    echo -e "\033[1;32m----------------------------------------\033[0m"
	    echo -e "\033[1;32mSearching for Backdoor Files...\033[0m"
	    echo -e "\033[1;32m----------------------------------------\033[0m"

	    echo -e "\033[1;34mTarget Directory: $target_dir\033[0m"
	    grep -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|fclose|readfile) *\(" "$target_dir"

	    echo ""
	    echo -e "\033[1;33mRecommendation: If any suspicious files are found, consider isolating the system for further investigation.\033[0m"
            ;;
        8)
            while true; do
                display_access_log_menu
		default_logfile=$( [ -f /var/log/apache2/access.log ] && echo /var/log/apache2/access.log || ([ -f /var/log/httpd/access.log ] && echo /var/log/httpd/access.log || ([ -f /var/log/nginx/access.log ] && echo /var/log/nginx/access.log)))
		echo ""
		echo -e "\033[1;32mPlease enter the path to the access log file (press Enter to use default: $default_logfile):\033[0m"
		read logfile
		logfile=${logfile:-$default_logfile}
                case $access_choice in
                    1)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mMost Frequent IP Accesses:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
			awk '{print $1}' "$logfile" | sort | uniq -c | sort -nr
                        ;;
                    2)
			read -p "Enter IP address to search: " ip_search
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mActivity of IP $ip_search:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        grep "$ip_search" "$logfile"
                        ;;
                    3)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mMost Frequently Accessed Pages/URLs:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        awk '{print $7}' "$logfile" | sort | uniq -c | sort -nr
                        ;;
                    4)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mDistribution of Status Codes:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        awk '{print $9}' "$logfile" | sort | uniq -c | sort -nr
                        ;;
                    5)
                        read -p "Enter status code to search: " status_code
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mSearching for Status Code $status_code:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        awk -v code="$status_code" '$9 == code' "$logfile" | awk '{print $1}' | sort | uniq -c
                        ;;
                    6)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mBusiest Server Times:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        awk -F: '{print $2":"$3}' "$logfile" | sort | uniq -c | sort -nr
                        ;;
                    7)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mDistribution of User-Agents:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        awk -F\" '{print $6}' "$logfile" | sort | uniq -c | sort -nr
                        ;;
                    8)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mActivity by HTTP Method:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        awk '{print $6}' "$logfile" | cut -d'"' -f2 | sort | uniq -c | sort -nr 
                        ;;
                    9)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mSQL Injection Payloads:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        grep -Ei "union|select|insert|drop|update|delete|load_file|outfile|version|database|concat" "$logfile" | less
                        ;;
                    10)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mXSS Payloads:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        grep -Ei "<script>|%3Cscript%3E" "$logfile" | less
                        ;;
                    11)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mLFI/RFI Payloads:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        grep -Ei "/etc/passwd|access.log|auth.log" "$logfile" | less 
                        ;;
                    12)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mAdmin Page Access Attempts:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        grep -Ei "admin|administrator|adm|backend|cpanel|myadmin|phpmyadmin" "$logfile" | less
                        ;;
                    13)
                        break
                        ;;
                    *)
                        echo -e "\033[1;31mInvalid choice. Please select a valid option.\033[0m"
                        ;;
                esac
                echo ""
            done
            ;;
        9)
            while true; do
                display_auth_log_menu
		default_authlog=$( [ -f /var/log/auth.log ] && echo /var/log/auth.log || ([ -f /var/log/secure ] && echo /var/log/secure || echo /var/log/messages))
		echo ""
		echo -e "\033[1;32mPlease enter the path to the auth log file (press Enter to use default: $default_authlog):\033[0m"
		read logfile
		authlog=${authlog:-$default_authlog}
 
                case $access_choice in
            1)
                echo -e "\e[1;32m" # Green color
                echo "Failed login attempts:"
                grep -a "Failed password" "$authlog"
                grep -a "Failed password" $authlog | awk '{print $(NF-3), $(NF-1)}' | sort | uniq -c | sort -nr
                echo -e "\e[0m" # Reset color
                ;;
            2)
                echo -e "\e[1;32m" # Green color
                echo "Authentication failures:"
                grep -a "authentication failure" "$authlog"
                echo -e "\e[0m" # Reset color
                ;;
            3)
                echo -e "\e[1;32m" # Green color
                echo "Successful logins:"
                grep -a "Accepted password" "$authlog"
                grep -a "Accepted password" "$authlog" | awk '{print $(NF-3), $(NF-1)}' | sort | uniq -c | sort -nr
                echo -e "\e[0m" # Reset color
                ;;
            4)
                echo -e "\e[1;32m" # Green color
                echo "Uses of sudo or su:"
                grep -a "sudo:" "$authlog"
                grep -a "su:" "$authlog"
                echo -e "\e[0m" # Reset color
                ;;
            5)
                echo -e "\e[1;32m" # Green color
                echo "SSH key usage:"
                grep -a "Accepted publickey" "$authlog"
                echo -e "\e[0m" # Reset color
                ;;
            6)
		echo ""
		grep -a -oP '(?<=from\s)([0-9]{1,3}\.){3}[0-9]{1,3}' "$authlog" | sort | uniq
                read -p "Enter IP address to analyze: " ip
                echo -e "\e[1;32m" # Green color
                echo "Login attempts from IP address $ip:"
                grep -a "$ip" "$authlog"
                echo -e "\e[0m" # Reset color
                ;;
            7)
		echo ""
		cat /etc/passwd | grep /bin/bash 
		echo ""
                read -p "Enter username to analyze: " user
                echo -e "\e[1;32m" # Green color
                echo "Activity of user $user:"
                grep -a "$user" "$authlog"
                echo -e "\e[0m" # Reset color
                ;;
            8)
                break
                ;;
            *)
                echo -e "\e[1;31m" # Red color
                echo "Invalid choice. Please enter a number between 1 and 8."
                echo -e "\e[0m" # Reset color
                ;;
            esac
            done
	    ;;
	10)
	     while true; do
    	     echo -e "\033[1;34m************************************************************\033[0m"
    	     echo -e "\033[1;34mSystem log Analysis:\033[0m"
             echo -e "\033[1;34m************************************************************\033[0m"
 
    	     echo "1) View recent system errors"
   	     echo "2) View recent anomalies or unusual activity"
    	     echo "3) Search for specific error messages"
    	     echo "4) Analyze logs by IP address"
    	     echo "5) Exit"
    
    	     default_syslog=$( [ -f /var/log/syslog ] && echo /var/log/syslog || echo /var/log/messages )
    	     read -p "Enter your choice (1-5): " choice
    	     echo -e "\e[1;32mPlease enter the path to the syslog file (press Enter to use default: $default_syslog):\e[0m"
    	     read logfile
    	     logfile=${logfile:-$default_syslog}

    		case $choice in
            1)
            	echo -e "\e[1;32mRecent system errors:\e[0m"
            	grep -i "error" "$logfile" | tail -n 20
            	echo ""
            	;;
            2)
            	echo -e "\e[1;32mRecent anomalies or unusual activity:\e[0m"
            	grep -i -e "fail" -e "warning" -e "alert" "$logfile" | tail -n 20
            	echo ""
            	;;
            3)
            	echo ""
            	read -p "Enter error message to search for: " search_term
            	echo -e "\e[1;32mSearching for '$search_term':\e[0m"
            	grep -i "$search_term" "$logfile"
            	echo ""
            	;;
            4)
            	echo ""
            	grep -oP '(?<=from\s)([0-9]{1,3}\.){3}[0-9]{1,3}' "$logfile" | sort | uniq
            	read -p "Enter IP address to analyze: " ip
            	echo -e "\e[1;32mLog entries from IP address $ip:\e[0m"
            	grep -i "$ip" "$logfile"
            	echo ""
            	;;
            5)
            	break
            	;;
            *)
            	echo -e "\e[1;31mInvalid choice. Please enter a number between 1 and 5.\e[0m"
            	echo ""
            	;;
	    esac
	    done
	    ;;
        11)
	    echo "Exiting script..."
            exit 0
            ;;
        *)
            echo -e "\033[1;31mInvalid choice. Please select a valid option.\033[0m"
            ;;
    esac

    echo ""
done
