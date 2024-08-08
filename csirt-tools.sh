#!/bin/bash

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
    echo "2) Check Process, Service, Apps and StarUp"
    echo "3) Check Network Communication"
    echo "4) Check User"
    echo "5) Check Directory Listings"
    echo "6) Check Writable Directory/Files/SUID"
    echo "7) Check Backdoor Files"
    echo "8) Check Access Log"
    echo "9) Check Auth Log"
    echo "10) Exit"
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
	    echo -e "\033[1;34mView Disk Usage:\033[0m"
	    df -h
	    echo ""
	    lsblk
	    echo ""
	    echo -e "\033[1;34mView RAM Usage:\033[0m"
	    free -mh
	    echo ""
            echo -e "\033[1;33mRecommendation: Check for known vulnerabilities or patches related to the detected system version.\033[0m"
            ;;
        2)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mProcess, Service, Apps and StartUp Information:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
	    echo -e "\033[1;34mView running all process:\033[0m"
            ps -aux
            echo ""
	    echo -e "\033[1;34mView the current user process:\033[0m"
            ps -ef | grep -v '^root' | grep -E '/tmp|/dev/shm|nc|curl|wget|bash|sh|python|perl|php'
            echo ""
	    echo -e "\033[1;34mView all services that are set to run at startup:\033[0m"
     	    systemctl list-unit-files --type=service | grep enabled
            echo ""
            echo -e "\033[1;34mView the status of running services:\033[0m"
	    systemctl list-units --type=service --state=running
            echo ""
            echo -e "\033[1;34mView Installed Packages:\033[0m"
	    dpkg -l
 	    echo ""
            echo -e "\033[1;34mDisplay Crontab for Each User:\033[0m"
            for user in $(cut -f1 -d: /etc/passwd); do echo "Crontab for $user:"; crontab -u $user -l; echo ""; done
            echo -e "\033[1;33mRecommendation: Review running processes and startup for any suspicious activity or unknown services.\033[0m"
            ;;
        3)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mNetwork Communication Information:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;34mView Inbound Connections:\033[0m"
            netstat -tulnp | head -20
            echo ""
            echo -e "\033[1;34mView Outbound Connections:\033[0m"
            netstat -antup | head -20
            echo ""
            echo -e "\033[1;34mView Established Connections:\033[0m"
            netstat -antup | grep "ESTA"
            echo ""
            echo -e "\033[1;34mView Firewall:\033[0m"
            echo ""
            iptables -L -v -n
	    echo ""
            echo -e "\033[1;34mView Connected Users:\033[0m"
            w
            echo ""
            echo -e "\033[1;34mView DNS Configuration:\033[0m"
            cat /etc/resolv.conf
            echo ""
            echo -e "\033[1;34mView Hostname:\033[0m"
            cat /etc/hostname
            echo ""
            echo -e "\033[1;34mView Hosts File:\033[0m"
            cat /etc/hosts
            echo ""
            echo -e "\033[1;33mRecommendation: Monitor network traffic for unusual connections, and verify the legitimacy of established connections.\033[0m"
            ;;
        4)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mUser Information:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;34mView Users:\033[0m"
            cat /etc/passwd
            echo ""
            echo -e "\033[1;34mView Users with Bash:\033[0m"
            cat /etc/passwd | grep "bash"
            echo ""
            echo -e "\033[1;34mView Last Logins:\033[0m"
            lastlog
            last
            echo ""
            echo -e "\033[1;34mView currently logged-in users:\033[0m"
            w
            echo ""
            echo -e "\033[1;34mView Users with Sudo:\033[0m"
            getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | while read user; do echo "User: $user"; sudo -l -U $user; echo "--------------------------------"; done
            echo ""
 
            echo -e "\033[1;33mRecommendation: Validate user accounts and review login history for unauthorized access.\033[0m"
            ;;
        5)
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mDirectory Listings:\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;34mHome Directory:\033[0m"
            ls -alrt -R /home | head -20
            echo ""
            echo -e "\033[1;34mWWW Directory:\033[0m"
            ls -alrt -R /var/www | head -20
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
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;32mSearching for Backdoor Files...\033[0m"
            echo -e "\033[1;32m----------------------------------------\033[0m"
            echo -e "\033[1;34mHome Directory:\033[0m"
            grep -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|fclose|readfile) *\(" /home/ | head -20
            echo ""
            echo -e "\033[1;34mWWW Directory:\033[0m"
            grep -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|fclose|readfile) *\(" /var/www/ | head -20
            echo ""
            echo -e "\033[1;33mRecommendation: If any suspicious files are found, consider isolating the system for further investigation.\033[0m"
            ;;
        8)
            while true; do
                display_access_log_menu
		logfile=$( [ -f /var/log/apache2/access.log ] && echo /var/log/apache2/access.log || ([ -f /var/log/httpd/access.log ] && echo /var/log/httpd/access.log || ([ -f /var/log/nginx/access.log ] && echo /var/log/nginx/access.log)))
                case $access_choice in
                    1)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mMost Frequent IP Accesses:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
			awk '{print $1}' "$logfile" | sort | uniq -c | sort -nr | head -20
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
                        awk '{print $7}' "$logfile" | sort | uniq -c | sort -nr | head
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
                        awk -F: '{print $2":"$3}' "$logfile" | sort | uniq -c | sort -nr | head
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
                        grep -Ei "union|select|insert|drop|update|delete|load_file|outfile|version|database|concat" "$logfile" 
                        ;;
                    10)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mXSS Payloads:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        grep -Ei "<script>|%3Cscript%3E" "$logfile" 
                        ;;
                    11)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mLFI/RFI Payloads:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        grep -Ei "/etc/passwd|access.log|auth.log" "$logfile" 
                        ;;
                    12)
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        echo -e "\033[1;32mAdmin Page Access Attempts:\033[0m"
                        echo -e "\033[1;32m----------------------------------------\033[0m"
                        grep -Ei "admin|administrator|adm|backend|cpanel|myadmin|phpmyadmin" "$logfile"
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
		authlog=$( [ -f /var/log/auth.log ] && echo /var/log/auth.log || ([ -f /var/log/secure ] && echo /var/log/secure || echo /var/log/messages))
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
            echo "Exiting script..."
            exit 0
            ;;
        *)
            echo -e "\033[1;31mInvalid choice. Please select a valid option.\033[0m"
            ;;
    esac

    echo ""
done

