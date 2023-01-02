<h1 align="center">
  Pristine Hosting
</h1>

<h4 align="center">Creating a Fast, Scalable Secure Hosting Service</h4>

## Contents

* [Deciding for a VPS hosting service](#deciding-for-a-vps-hosting-service)
* [Account Flow](#account-flow)


### Deciding for a VPS hosting service
* Make a VPS on your favorite hosting provider i.e AWS, Digital Ocean, Google Cloud, Vultr etc.

### Account Flow
1. Login to the account, secure it with 2-factor auth.
2. Create server instance.
3. Choose Cloud Compute(VPS)
4. Choose Intel Regular - for test env
5. Choose Server location
6. Choose Server Image - Ubuntu 22.04 LTS
7. Choose server size
8. Enable/disable auto backup
9. Disable ipv6
10. Add Server hostname
11. SSH on your new server. ```ssh root@<ip>```
12. Change password ```passwd```
13. Add non-root user ```adduser <name>```
14. List dir ```ls /home```
15. Delete user ```deluser ubuntu --remove-home```
16. Change password of current user ```passwd <name>```
17. Set default text editor ```update-alternatives --config editor```
18. Set user privileges of new user ```visudo```
19. Disable root login ```vi /etc/ssh/sshd_config``` ```PermitRootLogin no```
20. Make backup of ssh config file ```cp sshd_config sshd_config.bak```
21. Store back to original file from backup ```cp sshd_config.bak sshd_config```
22. Restart services after changing configuration ```systemctl restart ssh```
23. Clear sudo cache ```sudo -k```

### Basic Server Hardening
1. Enable SSH login ```ssh-copy-id -i .ssh/id_rsa.pub <name>@<ip>``` 
2. Put this on ssh_config file 
```
PermitRootLogin no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
PasswordAuthentication no
```
3. Restart ssh service ```sudo systemctl restart ssh```
4. Local ssh config file ```sudo vi ~/.ssh/config```
```
Host myserver
Hostname 45.76.36.153
User will
IdentityFile ~/.ssh/id_rsa
ServerAliveInterval 60
ServerAliveCountMax 120 
```
5. Update server ```sudo apt update```
6. Upgrade server ```sudo apt upgrade```
7. Remove obsolete packages server ```sudo apt autoremove```
8. Reboot ```sudo reboot```
9. Firewall - lock the server, only allow  22, 443, 80 -- use cloud firewall
> Vultr Firewall [@firewall](https://www.vultr.com/docs/firewall-quickstart-for-vultr-cloud-servers/#Which_Firewall_Does_My_Server_Use_)
![VultrFirewall.png](diagrams%2FVultrFirewall.png)
10. ```sudo ufw status verbose```
10. ```sudo ufw allow http```
11. ```sudo ufw allow https/tcp```
12. ```sudo ufw default deny incoming```
13. ```sudo ufw default allow outgoing```
14. ```sudo ufw allow ssh```
15. ```sudo ufw enable```
16. Make a firewall group on vultr - configure it and linked the instance to your current server.
17. Only allow your ip to ssh
18. Block unwanted ips that are trying to request too many login attempts
19. Install Fail2Ban 
```
sudo apt update
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl status fail2ban
cd /etc/fail2ban
sudo cp jail.conf jail.local
```
20. config file is jail.conf
21. Ban the host for 7days ```bantime  = 604800s```
22. If you exceed the maxretry on a specified findtime host is banned for the bantime ```findtime  = 30800s```
22. Set maxretry to 3 times ```maxretry  = 3```
23. Too long find time will result to wasted cpu cycles and memory usage
24. Use aggressive sshd ```mode=aggressive```
24. ```enabled=true```
24. ```sudo systemctl restart fail2ban```
25. ```/var/log/fail2ban.log```
25. ```sudo less /var/log/fail2ban.log```
26. Unban an Ip ```sudo fail2ban-client set sshd unbanip <ip>```

### Hardened and optimize server distribution/OS (Performance and Security)
1. Set the timezone of the server. 
```
sudo timedatectl
sudo timedatectl list-timezones
sudo timedatectl list-timezones | grep <City>
sudo timedatectl set-timezone Europe/Amsterdam
```
2. SWAP - space on disk allocated when physical memory is full.
3. Verify swap status ```htop```
4. Change Swapiness and cache pressure
```
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak
add at the end of the file
vm.swappiness = 1
vm.vfs_cache_pressure = 50

sudo sysctl -p
allocate 1g of swapfile
sudo fallocate -l 1G /swapfile
change swapfile permission
sudo chmod 600 swapfile
sudo mkswap /swapfile
enable swap file
sudo swapon /swapfile

Ensure that swapfile persists after a server reboots
cp /etc/fstab /etc/fstab.bak
/swapfile swap swap defaults 0 0

sudo reboot
cp /etc/sysctl.conf /etc/sysctl.conf.bak
enable changes 
sudo sysctl -p
```
5. Shared memory space - used to exchange data between programs
6. Lock down shared memory space - Secure the shared memory
```
sudo vi fstab
none /run/shm tmpfs defaults,ro 0 0
# none /run/shm tmpfs rw,noexec,nosuid,nodev 0 0
sudo reboot

mount
Make sure these lines are there:
none on /run/credentials/systemd-sysusers.service type ramfs (ro,nosuid,nodev,noexec,relatime,mode=700)
none on /run/shm type tmpfs (ro,relatime,inode64)
```
7. Harden and optimize the network layer
```
allows admin to change kernel parameters
sudo sysctl -a
sudo vi sysctl.conf
uncomment these lines:
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

enable changes:
sudo sysctl -p

# Increase number of usable ports:
net.ipv4.ip_local_port_range = 1024 65535

# Increase the size of file handles and inode cache and restrict core dumps:
fs.file-max = 2097152
fs.suid_dumpable = 0

# Change the number of incoming connections and incoming connections backlog:
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 262144

# Increase the maximum amount of memory buffers:
net.core.optmem_max = 25165824

# Increase the default and maximum send/receive buffers:
net.core.rmem_default = 31457280
net.core.rmem_max = 67108864
net.core.wmem_default = 31457280
net.core.wmem_max = 67108864

enable changes:
sudo sysctl -p
```
7. Install a system tuning tool - optimized and configured for performance
profile-base system tuning tool - for static and dynamic tuning of systems
```
sudo apt update
sudo apt install tuned
sudo tuned-adm list
sudo tuned-adm profile <profile-name-from-list>
sudo tuned-adm profile throughput-performance
sudo tuned-adm active
```
8. Congestion Control
    - Congestion Control Algo decide how fast to send data.
    - Implement BBR and RTT throughput.
    - BBR uses latency instead of lost packets as a primary factor to determine how fast the sending rate should be.
9. List all available congestion control algo.
```
List available congestion control algorithms:
sudo sysctl net.ipv4.tcp_available_congestion_control

List your current congestion control setting:
sudo sysctl net.ipv4.tcp_congestion_control

To enable BBR, need enable kernel module tcp_bbr:
sudo modprobe tcp_bbr
sudo bash -c 'echo "tcp_bbr" > /etc/modules-load.d/bbr.conf'

After modprobe tcp_bbr, bbr should be available in the list of tcp_available_congestion_control:
sudo sysctl net.ipv4.tcp_available_congestion_control
```
10. File Access Time - Disable file access times, it's seldom useful and causes an io operation every time file is read.
```
Check default parameters after the server booted:
cat /proc/mounts
Look for this line:
/dev/vda1 / ext4 rw,relatime 0 0

Add this line to fstab file:
sudo vi /etc/fstab
/dev/disk/by-uuid/f9119fcd-716a-45d9-ba7c-e145c5b95fe2 / ext4 defaults,noatime 0 1
sudo reboot
cat /proc/mounts
Look for this line:
/dev/vda1 / ext4 rw,noatime 0 0
```
11. Open File Limits -Since sockets are considered files on a linux system, this limit the concurrent connections as well.
    - maximum number of open files allowed per process
    - Hard limit is the maximum value of the soft limit
    - Soft limit is used to limit the system resources for running non-root processes. 
      - Can't exceed hard limit.
    - Make sure to set the open file limits to each of these stacks: nginx | mariadb | php
```
ulimit -Hn
ulimit -Sn
cd /etc/security
sudo cp limits.conf limits.conf.bak
Add the following to the limits.conf file
    *       soft    nofile      999999
    *       hard    nofile      999999
    root    soft    nofile      999999
    root    hard    nofile      999999
    
sudo reboot
ulimit -Hn
ulimit -Sn

PLUGGABLE AUTHENTICATION MODULES (PAM)
You need to edit the following two files in the `/etc/pam.d/`` directory and 
add the directives as indicated to allow a higher value for the maximum open file limit:

The files are:
`common-session` and `common-session-noninteractive`

Make backup:
sudo cp common-session common-session.bak
sudo cp common-session-noninteractive common-session-noninteractive.bak

You need to add the following line to the file `common-session`:
session required pam_limits.so

The easiest way is to invoke a root shell:
sudo bash -c 'echo session required pam_limits.so >> /etc/pam.d/common-session'

You need to add the following line to the file `common-session-noninteractive`
session required pam_limits.so

The easiest way is to invoke a root shell:
sudo bash -c 'echo session required pam_limits.so >> /etc/pam.d/common-session-noninteractive'

Reboot the server to enable the above changes:
sudo reboot
```
12. Buy a domain name and configure dns settings in cloudflare
```
A        <your_domain>     <your_server_ip>     DNS only    Auto
CNAME    www               <your_domain>        DNS only    Auto
```

### Installing LEMP Stack
Only download official ubuntu package.
Ondrej nginx repo
Ondrej php repo
mariadb repo
```
sudo apt update && sudo apt upgrade

Search for a package:
sudo apt-cache search iftop
sudo apt-cache show iftop
sudo apt install iftop
sudo iftop
sudo apt remove iftop
sudo apt purge iftop

NGINX
sudo add-apt-repository ppa:ondrej/nginx
sudo apt install nginx libnginx-mod-http-cache-purge libnginx-mod-http-headers-more-filter
sudo systemctl status nginx

Fix this: (nginx and systemd are competing for resources)
host2204 systemd[1]: nginx.service: Failed to parse PID from file /run/nginx.pid: Invalid argument
sudo vi /usr/lib/systemd/system/nginx.service
Add this directive on [Service]:
ExecStartPost=/bin/sleep 1

sudo systemctl daemon-reload
sudo systemctl restart nginx
sudo systemctl status nginx
curl -I http://<your_server__ip>
curl -i http://<your_server__ip>

ls /var/www/html/
nginx -v

Make nginx start automatically after a reboot:
sudo reboot
sudo systemctl status nginx
sudo systemctl enable nginx

MARIADB
curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | sudo bash
sudo apt install mariadb-server mariadb-client
sudo systemctl status mariadb


PHP8.1
sudo add-apt-repository ppa:ondrej/php
sudo apt install php8.1-{fpm,gd,mbstring,mysql,xml,xmlrpc,opcache,cli,zip,soap,intl,bcmath,curl,imagick,ssh2}

Check the status of php-fpm
sudo systemctl status php8.1-fpm
```
![phpfpm.png](diagrams%2Fphpfpm.png)


### Server Mail
- Configure the server to send mail without plugins.
- MSMTP mail provider -  lightweight mail client
- Get msmtp password on Google account: 2 factor has to enabled to get this.
```
sudo apt install msmtp msmtp-mta
sudo vi .msmtprc

Put this config:
# Modify DIRECTIVES in CAPS
defaults
# Set Account Name
account gmail
# TLS Directives - Do Not Modify
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
# Set Host Information
host smtp.gmail.com
port 587
auth on
user <my_email>
password <my_password>
from <my_email>
# Set Account Default
account default : gmail

sudo chmod 600 .msmtprc

Test sending of mail from cli:
msmtp <email>
type a message
ctrl+d

ls /etc/apparmor.d/ -l
ls /etc/apparmor.d/disable/ -l
```
- Configure php mailer
```
Create a new config file:
sudo cp .msmtprc /etc/msmtprc
cd /etc
sudo chown www-data msmtprc
sudo chmod 600 msmtprc

Edit the php.ini and specify the path to send mail:
cd /etc/php/8.1/fpm/
sudo cp php.ini php.ini.bak
sudo vi php.ini

put this after sendmail portion:
sendmail_path = "/usr/bin/msmtp -C /etc/msmtprc -t"

sudo systemctl restart php8.1-fpm && sudo systemctl reload nginx
cd
vi php_mail_test.php
ls /home/ -l
cd /home
sudo chmod 755 will/
cd
sudo -u www-data php php_mail_test.php
cd /home
sudo chmod 750 andrew/
rm php_mail_test.php
```

### In-Depth NGINX
- directives, contexts - location context modifiers, try_files directive
- Nginx consists of modules controlled by directives.
- Directives consist of an option or parameter name followed by the option or parameter value.
- Directives end with a semicolon
- Context - Also a directive that encloses other directives {}
  - main, events, http, server, location
  - child context will override parent context
  - response depends on the modifier
```
cd /etc/nginx/sites-available/
sudo vi default
Change 
root /var/www/html; to roots /var/www/html;
sudo nginx -t
fix syntax error
set unset file line numbers in vi:
:set nu! 
sudo nginx -t
sudo systemctl reload nginx
```
![nginxContext.png](diagrams%2FnginxContext.png)
![locationModifiers.png](diagrams%2FlocationModifiers.png)
- exact modifier 
  - `location = /xmlrpc.php { deny all; }` will only have this `example.com/xmlrpc.php`
- no modifier - prefix match that's case-sensitive
  - `location = /tax { return 301 example.com; }` will only have this `example.com/tax*`
  - regular exp match `(~and~*)` - `case sensitive ~`  `case insensitive ~*`
  - `location ~ \.ico$ { deny all; }` will only have this `.ico`
  - `location ~* \.ico$ { deny all; }` will also have this `.ICo`
- try_files directive - checks the existence of files in the specified order 
  and uses the first found file for request processing.
    - `location / { try_files $uri $uri/ /other/index.html; }` 
    - if it exists, serve it `/var/www/example.com/public_html/image.jpg`
    - if not move to the next condition
    - wp pretty permalinks
        - `location / { try_files $uri $uri/ /index.php$is_args$args; }`
    - usage
      ![try_files.png](diagrams%2Ftry_files.png)


### Harden and optimize NGINX
- default nginx config is secure
- improve performance and security
- 'include' directive - use to organize config files
```
cd /etc/nginx/
sudo mkdir includes/
sudo cp nginx.conf nginx.conf.bak
sudo vi nginx.conf

MAIN CONTEXT
Add the following directives to the main context: (after `worker_processes auto;`)
worker_rlimit_nofile 30000;
worker_priority -10;
timer_resolution 100ms;
pcre_jit on;

EVENTS CONTEXT
Modify and add the following directives to the events context:
worker_connections 4096;
accept_mutex on;
accept_mutex_delay 200ms;
use epoll;

sudo nginx -t
cd /etc/nginx/includes
sudo touch basic_settings.conf buffers.conf timeouts.conf file_handle_cache.conf gzip.conf brotli.conf
ls -l

sudo vi basic_settings.conf
# BASIC SETTINGS - Deals with optimization and security
 i.e. specifying the character is important because it lets the browser know how it should display the web page.
 Provides the browser the ability to to begin parsing hence reduced latency time.
 Turn server tokens off to prevent info leakage

charset utf-8;
sendfile on;
sendfile_max_chunk 512k;
tcp_nopush on;
tcp_nodelay on;
server_tokens off;
more_clear_headers 'Server';
more_clear_headers 'X-Powered';
server_name_in_redirect off;
server_names_hash_bucket_size 64;
variables_hash_max_size 2048;
types_hash_max_size 2048;

include /etc/nginx/mime.types;


sudo vi buffers.conf
# BUFFERS - region in memory storage used temporarily store data while it is being moved from one place to another.
    - Also used in moving data betwwen processes within a computer.
    - Setting too low, nginx will constantly use io to write remaining parts to file.
    - Setting too high, nginx will make yourself vulnerable to DDoS attacks where the attacker can open all server connections.
    - By limiting the buffers you prevent clients from overwhelming the resources of the server.
    - reduce this to 16m later -> client_max_body_size 100m;

client_body_buffer_size 256k;
client_body_in_file_only off;
client_header_buffer_size 64k;
# client max body size - reduce size to 16m after setting up site
# Large value is to allow theme, plugins or asset uploading.
client_max_body_size 100m;
connection_pool_size 512;
directio 4m;
ignore_invalid_headers on;
large_client_header_buffers 8 64k;
output_buffers 8 256k;
postpone_output 1460;
request_pool_size 32k;


sudo vi timeouts.conf
# TIMEOUTS - http persitent connections - the web server saves open connections which consumes CPU time and memory.
    - It sits when the connections are closed.
    - Connections are closed after a specified period of inativity.
    - It ensures that the connections do not persist indefinitely.

keepalive_timeout 5;
keepalive_requests 500;
lingering_time 20s;
lingering_timeout 5s;
keepalive_disable msie6;
reset_timedout_connection on;
send_timeout 15s;
client_header_timeout 8s;
client_body_timeout 10s;


sudo vi gzip.conf
# GZIP - Enabling gzip will reduce the weight of the response, hence the request will appear faster on the client side.

gzip on;
gzip_vary on;
gzip_disable "MSIE [1-6]\.";
gzip_static on;
gzip_min_length 1400;
gzip_buffers 32 8k;
gzip_http_version 1.0;
gzip_comp_level 5;
gzip_proxied any;
gzip_types text/plain text/css text/xml application/javascript application/x-javascript application/xml application/xml+rss application/ecmascript application/json image/svg+xml;


sudo vi brotli.conf
# BROTLI - Also enable brotli compression - Will show on Accept encoding request header.

brotli on;
brotli_comp_level 6;
brotli_static on;
brotli_types application/atom+xml application/javascript application/json application/rss+xml application/vnd.ms-fontobject application/x-font-opentype application/x-font-truetype application/x-font-ttf application/x-javascript application/xhtml+xml application/xml font/eot font/opentype font/otf font/truetype image/svg+xml image/vnd.microsoft.icon image/x-icon image/x-win-bitmap text/css text/javascript text/plain text/xml;


sudo vi file_handle_cache.conf
# FILE HANDLE CACHE - Will cache metadata about the file but not the content.

open_file_cache max=50000 inactive=60s;
open_file_cache_valid 120s;
open_file_cache_min_uses 2;
open_file_cache_errors off;

# Buffer Settings
include /etc/nginx/includes/buffers.conf;

# Timeout Settings
include /etc/nginx/includes/timeouts.conf;

# File Handle Cache Settings
include /etc/nginx/includes/file_handle_cache.conf;

Include the files to main config:
cd ..
sudo vi nginx.conf
user www-data;
worker_processes auto;
worker_rlimit_nofile 30000;
worker_priority -10;
timer_resolution 100ms;
pcre_jit on;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 4096;
        accept_mutex on;
        accept_mutex_delay 200ms;
        use epoll;
}

http {

        # Basic Settings
        include /etc/nginx/includes/basic_settings.conf;
        # Buffer Settings
        include /etc/nginx/includes/buffers.conf;
        # Timeouts Settings
        #include /etc/nginx/includes/timeouts.conf;

        ##
        # Logging Settings
        ##

        access_log off;
        # access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        # Gzip Settings
        include /etc/nginx/includes/gzip.conf;
        # Brotli Settings
        include /etc/nginx/includes/brotli.conf;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}


sudo nginx -t
sudo systemctl reload nginx

On 'too many open files error'
- check current limit, increse limit, confirm new limit
Get nginx process ID:
ps aux | grep www-data
view open file limits:
cat /proc/nginx_pId/limits
sudo vi nginx.conf
sudo systemctl reload nginx
```

- Bash Aliases
```
cd
nano .bash_aliases
alias supd='sudo apt update && sudo apt upgrade && sudo apt autoremove'
alias ngt='sudo nginx -t'
alias ngr='sudo systemctl reload nginx'
alias fpmr='sudo systemctl restart php8.1-fpm'
alias ngsa='cd /etc/nginx/sites-available/ && ls'
alias ngin='cd /etc/nginx/includes/ && ls'
su <user>
```

## Harden and optimize MariaDB
```
cd
sudo mysql_secure_installation
Enter current password for root (enter for none): [Enter]
Switch to unix_socket authentication [Y/n] n
Change the root password? [Y/n] n
Remove anonymous users? [Y/n] y
Disallow root login remotely? [Y/n] y
Remove test database and access to it? [Y/n] y
Reload privilege tables now? [Y/n] y

sudo mysql
sudo mysql -uroot

Confirm the swappiness value:
sudo sysctl -a | grep swappiness
Increase to 5:
sudo sysctl -w vm.swappiness=5

show databases;
show schema;

cd /etc/mysql/mariadb.conf.d/
sudo cp 50-server.cnf 50-server.cnf.bak
sudo vi 50-server.cnf

Put this:
# Performance Schema
performance_schema=ON
performance-schema-instrument='stage/%=ON'
performance-schema-consumer-events-stages-current=ON
performance-schema-consumer-events-stages-history=ON
performance-schema-consumer-events-stages-history-long=ON
```

- Mysql query cache - Stores the results of a query
  - caching is good except in this case, takes longer to return 
  - a result from the cache faster to query the dataset directory
  - ensure query cache is disabled.
```
sudo mysql
show variables like 'have_query_cache';
show variables like 'query_cache_%';

alias supd='sudo apt update && sudo apt upgrade && sudo apt autoremove'
alias ngt='sudo nginx -t'
alias ngr='sudo systemctl reload nginx'
alias fpmr='sudo systemctl restart php8.1-fpm'
alias ngsa='cd /etc/nginx/sites-available/ && ls'
alias ngin='cd /etc/nginx/includes/ && ls'
alias mdbrs='sudo systemctl restart mariadb'
alias sumys='sudo mysql'
```

- Mysql dns lookups - new client connection 
  - thread created to handle the request
  - checks if clients hostname is in the host cache
  - if not, thread resolves ip to a hostname
  - then resolves it back to an ip 
  - this is time-consuming, dns lookups must be disabled
```
sudo vi 50-server.cnf
Put this to disable dns lookups:
Uncomment
#skip-name-resolve
skip-name-resolve
```

- Mariadb log files - size and space used by log files
  - size and space used by log files
  - can become a problem on small servers
  - server may run out of disk space
  - results in mariadb becoming "non-responsive"
  - reduce the number of log files
  - from 10(default) to 3 days
```
show variables like 'expire_logs_days';
SET GLOBAL expire_logs_days = 3;
flush binary logs;

sudo vi 50-server.cnf
Put this to set expire log files limit:
expire_logs_days = 3

mdbrs

show variables like 'expire_logs_days';
```

-- Innodb 
    - innodb buffer pool size
        - amount of memory allocated to the innodb buffer pool 
        - used to cache data and index blocks.
        - one of the most important settings
        - set to 80% of server RAM
    - innodb log file size
        - transaction or commit log
        - set to 25% of the innodb_buffer_pool_size
    - innodb resource allocation
        - innodb_buffer_pool_size -> 80% of total server memory
        - innodb_log_file_size -> 25% of the innodb_buffer_pool_size
        - monitor resources using htop
        - do not modify the innodb_log_file_size then restart mdb, innodb may be corrupted
            Procedure:
            - check log file size
            - stop mariadb
            - set innodb_log_file_size
            - start mariadb
            - check and confirm new log file size
```
htop
sumys

sudo vi 50-server.cnf
# InnoDB
innodb_buffer_pool_size = 800M
#innodb_log_file_size = 200M
sudo systemctl stop mariadb

sudo vi 50-server.cnf
# InnoDB
innodb_buffer_pool_size = 800M
innodb_log_file_size = 200M
sudo systemctl start mariadb

SHOW VARIABLES LIKE '%innodb_buffer%';
SHOW VARIABLES LIKE '%innodb_log%';
```

- Mysql tuner
  - Perl script that analyzes your mysql configuration and performance.
  - Makes recommendations which variables you should adjust in order to increase
  - performance and decrease resource usage.
  - run every 60 to 90 days, don't run continuously
  - task
```
cd 
mkdir MySQLTuner/
cd MySQLTuner/
wget http://mysqltuner.pl/ -O mysqltuner.pl
chmod +x mysqltuner.pl
run it:
sudo ./mysqltuner.pl
```

- Database optimization
  - Performed over a period of time
  - Higher is not always better
  - Use a conservative approach
  - No quick fixes
  - Reduce resource usage
  - Optimum performance
![mariadb.png](diagrams%2Fmariadb.png)

- "too many open files"
    - reached limit of many files
    - that process can have open
    - Procedure:
        - check current limit
        - increase limit
        - confirm new limit
```
get pid:
ps aux | grep mysql
View the open file limits:
cat /proc/<pid>/limits

cd /etc/systemd/system/
ll
If not exist create this dir:
sudo mkdir mariadb.service.d/

cd mariadb.service.d/
touch limits.conf
Put this:
[Service]
LimitNOFILE=40000

sudo systemctl daemon-reload
sudo systemctl restart mariadb
Verify:
ps aux | grep mysql
cat /proc/<pid>/limits
```


## Harden and optimize PHP81
- php 8.1 eol 25-10-24
- ubuntu/ondrej php 8.1 release supported until april 2027
- 50% faster than 7.4 and 8.0
- harden - remove dangerous settings
  - allow_url_fopen
  - cgi.fix_pathinfo
  - expose_php
- optimize
  - upload_max_filesize = 100M
  - post_max_size = 125M
  - max_execution_time = 30
  - max_input_time = 60
  - max_input_vars = 3000
  - memory_limit = 128M
  - memory_limit = 256M
- opcache 
- - caches the conversion of human-readable php to machine code.
  - validate_timestamp - determine how often opcache must check php files for updated code.
  - When php file is executed opcache checks the last time it was modified on disk
  - then compares this time with the last time it cached the compilation of the script.
  - If the file was modified after being cached, compile cache for the script 
  - will be generated.
  - Not necessary on production server as it will use unneeded cpu cycles.
  - dev server 
    - opcache.validate_timestamps=1
    - opcache.revalidate_freq=2
  - prod server
      - opcache.validate_timestamps=0
      - opcache.revalidate_freq=2
  - clearing opcache
    - cli
    - restart php-fpm
    - wp dashboard
    - plugin
    - w3tc

```
cd /etc/php/8.1/fpm
ll
sudo cp php.ini php.ini.bak
sudo vi php.ini

cd /etc/php/8.1/fpm
sudo vi php.ini
Search for allow_url_f
Search for cgi.fax_p
Search for expose_p

upload_max_filesize = 100M
post_max_size = 125M
max_execution_time = 30
max_input_time = 60
max_input_vars = 3000
memory_limit = 256M

Important to remember to also set the value in your wp-config.php file
opcache.enable=1

OPCACHE CONFIGURATION: DEVELOPMENT SERVER
opcache.memory_consumption=192
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=7963
opcache.validate_timestamps=1

OPCACHE CONFIGURATION: PRODUCTION SERVER
opcache.memory_consumption=192
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=7963
opcache.revalidate_freq=2
; Development Server
opcache.validate_timestamps=1
; Production Server
;opcache.validate_timestamps=0
opcache.revalidate_freq=2
```
- "too many open files"
    - reached limit of many files
    - that process can have open
    - Procedure:
        - check current limit
        - increase limit
        - confirm new limit
```
cd /var/www
find . -type f -print | grep php | wc -l

Determine the nginx process ID:
ps aux | grep php-fpm

View the open file limits using the cat command:
cat /proc/<pid>/limits

Open php-fpm.conf using nano:
cd /etc/php/8.1/fpm/
sudo cp php-fpm.conf php-fpm.conf.bak
sudo vi /etc/php/8.1/fpm/php-fpm.conf

Search for rlimit_files
rlimit_files = 32768
rlimit_core = unlimited 

Restart nginx and php-fpm
sudo systemctl reload nginx
sudo systemctl restart php8.1-fpm

Verify New Open File Limits: PHP-FPM
ps aux | grep php-fpm
cat /proc/<pid>/limits
```

### Server and site file dir structure
- web and doc root
  - default web root - /var/www/
  - doc root - /var/www/<your_domain_name>.com/public_html/
```
sudo apt update && sudo apt install tree
cd /var/www/
sudo mkdir <your_domain_name>.com/
rename dir:
sudo mv examle.net example.com
remove dir
rm -rf

Create bash script for multiple sites:
sudo mkdir bash_scripts
touch create_dirs.sh
#!/bin/bash
echo "what is your domain name?"
read domain
mkdir -p /var/www/$domain/public_html/
echo "Your site directories have been created"
ls -ld /var/www/$domain/public_html/

sudo chmod +x create_dirs.sh
sudo ./create_dirs.sh
```

### NGINX Server blocks
- Used to host and serve multiple sites. Server host in apache.
- Create server block in a file
```
/etc/nginx/sites-available
Create symlink for the server block from sites-available to the sites-enables dir
```
- create a server block file in sites-available
- create a symlink to the server block file in sites-enabled
- sites-enabled should reference the server block file in the sites-available dir
```
sites-available is included in /etc/nginx/nginc.conf
├── sites-available
│   └── default
├── sites-enabled
│   └── default -> /etc/nginx/sites-available/default
```
- Server block config
  - after creating a server block and symlink to /etc/nginx/sites-enabled
  - test the nginx config
  - reload nginx to enable the server block
  - difference between reload and restart
  - must use reload because restart stops and start the server, dropping all connection 
  - hence when there's an error sever will stop and never be able to start
  - in reload server will keep on running based on the old config that works.

Create a server block
- configure dns
- create server block
  - ports
  - domain (hostname)
  - site location
  - index file
  - pretty permalinks wp
  - php
  - logs
  - Additional directives
    - optimize the fastcgi process
    - browser (http) caching
    - > Http Caching [@httpCachingDocs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching)
- install site
```
cd /etc/nginx/sites-available
sudo vi default
sudo vi pristinehost.uk.conf
server {
    listen 80
    listen [::]:80;
    server_name example.com www.example.com;   
    root /var/www/example.com/public_html;   
    index index.php;
    location / {
        try_files $uri $uri/ /index.php$is_args$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;  // sets the directive that can be used to set the fastcgim params to values specific to the request
        fastcgi_pass unix:/run/php/php8.1-fpm.sock; // specifies the socket we want to use
        include /etc/nginx/includes/fastcgi_optimize.conf;
    }
    include /etc/nginx/includes/browser_caching.conf;
    access_log /var/log/nginx/access_example.com.log combined buffer=256k flush=60m; // each site must have its own log files
    error_log /var/log/nginx/error_example.com.log;
}
cd /etc/nginx/includes
sudo touch browser_caching.conf
```

- Browser Caching Conf
  - define when and where th caching occurs
```
location ~* \.(webp|3gp|gif|jpg|jpeg|png|ico|wmv|avi|asf|asx|mpg|mpeg|mp4|pls|mp3|mid|wav|swf|flv|exe|zip|tar|rar|gz|tgz|bz2|uha|7z|doc|docx|xls|xlsx|pdf|iso)$ {
    add_header Cache-Control "public, no-transform";
    access_log off;
    expires 365d;
}

location ~* \.(js)$ {
    add_header Cache-Control "public, no-transform";
    access_log off;
    expires 30d;
}

location ~* \.(css)$ {
    add_header Cache-Control "public, no-transform";
    access_log off;
    expires 30d;
}

location ~* \.(eot|svg|ttf|woff|woff2)$ {
    add_header Cache-Control "public, no-transform";
    access_log off;
    expires 30d;
}
```
- FastCGI optimization
```
cd /etc/nginx/includes/

sudo touch fastcgi_optimize.conf
sudo vi fastcgi_optimize.conf
fastcgi_connect_timeout 60;
fastcgi_send_timeout 180;
fastcgi_read_timeout 180;
fastcgi_buffer_size 512k;
fastcgi_buffers 512 16k;
fastcgi_busy_buffers_size 1m;
fastcgi_temp_file_write_size 4m;
fastcgi_max_temp_file_size 4m;
fastcgi_intercept_errors on;

Include on you sites server block conf: 
sudo vi <your_domain>.conf
include /etc/nginx/includes/fastcgi_optimize.conf;

Enable the server block:
ls sites-*
sudo ln -s /etc/nginx/sites-available/pristinehost.uk.conf /etc/nginx/sites-enabled/
removing suymlink;
rm symlink_name
```

### Install WP
```
sudo mysql
create database <your_db_name>;
grant all privileges on <your_db_name>.* to '<db_username>'@'localhost' identified by 'password';
REFRESH / ENABLE CHANGES
flush privileges;
VIEW PRIVILEGES
show grants for '<db_username>'@'localhost';
select host, user from mysql.user;
show databases;
use db_name;
show tables;
describe table_name;
drop user '<username>'@'localhost'

Generate random databse username and password:
cat /dev/urandom | tr -dc 'a-za-z0-9' | fold -w 10 | head -n 2

sudo mysql
create database db_name;
grant all privileges on <your_db_name>.* to '<db_username>'@'localhost' identified by 'password';
cat /dev/urandom | tr -dc 'a-za-z0-9' | fold -w 30 | head -n 2
```
- Install wp
  - wp config details
  - wp salts
  - table-prefix
  - allow direct updating of plugins and themes
  - disable the built-in plugin and theme editor
  - set wp memory limit
  - turn off automatic core updates
```
tree /var/www

cd
wget https://wordpress.org/latest.tar.gz
extract gzip:
tar xf latest.tar.gz
sudo rm latest.tar.gz
ls

cd wordpress/
mv wp-config-sample.php wp-config.php

/** Allow Direct Updating Without FTP */
define('FS_METHOD', 'direct');
/** Disable Editing of Themes and Plugins Using the Built In Editor */
define('DISALLOW_FILE_EDIT', 'true');
/** Increase WordPress Memory Limit */
define('WP_MEMORY_LIMIT', '256M');
/** TURN OFF AUTOMATIC UPDATES */
define('WP_AUTO_UPDATE_CORE', false );

Generat wp salt:
Browser: https://api.wordpress.org/secret-key/1.1/salt/
Terminal: curl -s https://api.wordpress.org/secret-key/1.1/salt/
```
- with or without www
```
cd
cd wordpress/
sudo mv * /var/www/example.com/public_html/
cd /var/www/example.com
sudo chown -R www-data:www-data public_html/
ls -l
```
Set permalinks
- set to postname

### Harden WP
- ssl cert
```
curl -I http://pristinehost.uk
check CNAME record;
curl -I http://www.pristinehost.uk
sudo apt install certbot

Tweak the config for optimal performance and security:
sudo certbot certonly --webroot -w /<path> -d example.com -d www.example.com
sudo certbot certonly --webroot -w /var/www/example.com/public_html/ -d example.com -d www.example.com
```
- nginx ssl config
  - create a diffie hellman params file
  - create a site specific include file
  - create a general ssl include file
  - create a secure nginx server block
- Diffie Hellman Params
  - generate a file dhparam.pem
  - an algorithm used to establish
  - a shared secret between two parties
  - method of exchanging cryptography keys
  - for use in symmetric encryption algorithms
  - define how openSSL performs the Diffie-Hellman key-exchange.
- site specific ssl conf file
  - site specific include file contains the absolute pth/location of the various cert files
  - this file is unique to each site
- general ssl config file for all sites
    - ssl conf file for all sites
    - this file contains the ssl directives that can be used by all our sites on the server
    - no need to recreate this file for ewach site
    - include the file in your sites nginx conf file for each additional site.
```
cd /etc/nginx/
sudo mkdir ssl/
cd ssl/
sudo openssl dhparam -out dhparam.pem 2048
ls
sudo vi /etc/nginx/ssl/ssl_example.com.conf

ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
# SSL STAPLING
ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

Write xxplanation on every line:
sudo vi /etc/nginx/ssl/ssl_all_sites.conf
# CONFIGURATION RESULTS IN A+ RATING AT SSLLABS.COM
# WILL UPDATE DIRECTIIVES TO MAINTAIN A+ RATING - CHECK DATE
# DATE: NOVEMBER 2022
ssl_session_cache shared:SSL:20m;
ssl_session_timeout 180m;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
# ssl_ciphers must be on a single line, do not split over multiple lines
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_dhparam /etc/nginx/ssl/dhparam.pem;
ssl_stapling on;
ssl_stapling_verify on;
# resolver set to Cloudflare
# timeout can be set up to 30s
resolver 1.1.1.1 1.0.0.1;
resolver_timeout 15s;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=31536000;" always;
# After settting up ALL of your sub domains - comment the above and uncomment the directive hereunder, then reload nginx
# add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; " always;
```
- nginx secure server blocks
  - add a new non-secure server block
  - to redirect all requests from http to https
  - modify the existing non-secure server block
  - convert the existing non-secure server block into a secure server block
  - don't change the www to non www redirect to avoid 'too many redirects' error
  - the site will keep in redirecting in a way that it'll never complete. (competing redirects)
```
cd /etc/nginx/sites-available
sudo vi <your_domain>.conf
server {
    listen 80;
    server_name example.com www.example.com;
    # ADD REDIRECT TO HTTPS: 301 PERMANENT 302 TEMPORARY
    return 301 https://example.com$request_uri;
}
 listen 443 ssl http2;
 
include /etc/nginx/ssl/ssl_example.com;
include /etc/nginx/ssl/ssl_all_sites.conf;

test redirect:
curl -I http://pristinehost.uk
curl -I http://www.pristinehost.uk

Purpose of HSTS Header:
hsts https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
https://www.ssllabs.com/ssltest/
```
- https everywhere
  - mixed content error messages
  - site serving secure and insecure content
  - open wp dashboard
  - settings|General
  - Change wp address (url) and the site address from http to https
  
- certbot commands
```
sudo certbot certificates
sudo certbot delete
sudo certbot renew
sudo certbot renew --dry-run
sudo certbot renew --force-renewal

sudo crontab -e
# m h dom mon dow   command
00 1 14,28 * * certbot renew --force-renewal
00 2 14,28 * * systemctl reload nginx
```
- cron maintenance
  - cron attempts to send mail to
  - the user who initiated the cron
  - no root server user & the root user
  - recommend you disable this behaviour
```
disable sending mail:
add >/dev/null 2>&1
to the end of the cron job
```
- http response headers
  - http headers are the core part of http requests ans responses
  - general headers
  - request headers
  - response headers
  - entity headers
```
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
```
- http response headers
    - X-Frame-Options      
    - X-Content-Type-Options      
    - X-XSS-Options      
    - Referrer-Policy     
    - Permissions(feature)-Policy     
    - Content-Security-Policy  
- http response headers
  - create an include file
  - add the directives to the include file
  - include the file in your sites
  - server block conf file
```
cd /etc/nginx/includes/
sudo vi http_headers.conf
# -------------------------------------------------------

# Add Header Referrer-Policy - Uncomment desired directive

# -------------------------------------------------------

#add_header Referrer-Policy "no-referrer";
#add_header Referrer-Policy "no-referrer-when-downgrade";
#add_header Referrer-Policy "origin";
#add_header Referrer-Policy "origin-when-cross-origin";
#add_header Referrer-Policy "same-origin";
#add_header Referrer-Policy "strict-origin";
add_header Referrer-Policy "strict-origin-when-cross-origin";
#add_header Referrer-Policy "unsafe-url";
# ------------------------------------------------------
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "sameorigin";
add_header X-XSS-Protection "1; mode=block";
add_header Permissions-Policy "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=self,payment=()";
# Keep CSP Commented until site setup is done, then complete the CSP lecture.
#add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'self';"


cd /etc/nginx/sites-available/
sudo vi example.com.conf
# Place ABOVE the php processing location block
include /etc/nginx/includes/http_headers.conf;

sudo nginx -t
sudo systemctl reload nginx
curl -I http://pristinehost.uk
curl -I http://www.pristinehost.uk

test on: securityheaders.com
Fix Content Security Policy when site is completed.
```
- ownership and permissions
  - secure wp using cli
  - use best practices when setting the ownership and permissions
  - wp codex
- ownership
  - 2 possible ownership schemes
  - www-data:www-data
  - $USER:www-data
- www-data:www-data
  - nginx is the owner and the group owner of the wp dir and files
  - issue free wp site admin
    - not the most secure scheme
    - principle of least privilege
    - permissions
    - dir 755 | files 644 | wp-config 400
      - not recommended for security purposes
    - some themes and plugins doesn't work correctly unless it's set to www-data:www-data
```
WWW-DATA:WWW-DATA
cd /var/www/example.com/
sudo chown -R www-data:www-data public_html/
sudo find /var/www/example.com/public_html/ -type d -exec chmod 755 {} \;
sudo find /var/www/example.com/public_html/ -type f -exec chmod 644 {} \;
```
- $USER:www-data
  - your non-root user is owner and www-data is the group user of wp dir and files
  - more secure env
  - restrict web server's write permissions
  - principle of least privilege
  - permissions
    - dir 755 | files 644 | wp-config 664 to 644
    - dir 775 files 664
  - more secure than www-data:www-data
  - few issues
  - client can't be independent
- who is going to administer the site?
- access to command line
- be able to change permissions
- client want issue free sites
```
$USER:WWW-DATA
cd /var/www/example.com/
sudo chown -R $USER:www-data public_html/
sudo find /var/www/example.com/public_html/ -type d -exec chmod 755 {} \;
sudo find /var/www/example.com/public_html/ -type f -exec chmod 644 {} \;
sudo find /var/www/example.com/public_html/wp-content/ -type d -exec chmod 775 {} \;
sudo find /var/www/example.com/public_html/wp-content/ -type f -exec chmod 664 {} \;
sudo chmod 400 wp-config.php
```

Relax Permissions prior to any core update:
```
cd /var/www/example.com/
sudo chown -R www-data:www-data public_html/
sudo find /var/www/site.com/public_html/ -type d -exec chmod 775 {} \;
sudo find /var/www/site.com/public_html/ -type f -exec chmod 664 {} \;
```

Harden Permissions after any core update:
```
cd /var/www/example.com/
sudo chown -R $USER:www-data public_html/
sudo find /var/www/example.com/public_html/ -type d -exec chmod 755 {} \;
sudo find /var/www/example.com/public_html/ -type f -exec chmod 644 {} \;
sudo find /var/www/example.com/public_html/wp-content/ -type d -exec chmod 775 {} \;
sudo find /var/www/example.com/public_html/wp-content/ -type f -exec chmod 664 {} \;
```

```
cd
cd bash_scripts/
vi ownership_permissions.sh
SCRIPT:

#!/bin/bash
echo "What is your domain name?"
read domain
echo "What is your non root server username?"
read nonroot

echo Changing Ownership and Permissions
sudo chown -R $nonroot:www-data /var/www/$domain/public_html/
sudo find /var/www/$domain/public_html/ -type d -exec chmod 775 {} \;
sudo find /var/www/$domain/public_html/ -type f -exec chmod 664 {} \;

# Restart the php-fpm process to clear the opcache
sudo systemctl restart php8.1-fpm
echo Please open the WP DASHBOARD and UPDATE WP and switch back to terminal AFTER COMPLETING the WP update
echo ------------------------------------------------------------
read -p "Finished Updating WordPress? Press ENTER to continue" y
echo ------------------------------------------------------------
sudo chown -R $nonroot:www-data /var/www/$domain/public_html/
sudo find /var/www/$domain/public_html/ -type d -exec chmod 755 {} \;
sudo find /var/www/$domain/public_html/ -type f -exec chmod 644 {} \;
sudo find /var/www/$domain/public_html/wp-content/ -type d -exec chmod 775 {} \;
sudo find /var/www/$domain/public_html/wp-content/ -type f -exec chmod 664 {} \;
# Restart the php-fpm process to clear the opcache
sudo systemctl restart php8.1-fpm
echo Changing Ownership and Permissions
echo DONE…


Set Permissions
chmod +x ownership_permissions.sh
To Run:
sudo ./ownership_permissions.sh

For installing plugins that need to create files in the root of wp files, give public_html 755
sudo chmod 755 public_html/
```

- harden wp using nginx directives
  - use nginx to block access to important wp files and dirs
  - block bad bots
  - bloch php execution
  - filter request methods and url query strings
  - block sql injection, common exploits
  - spam and certain user agents
  - easy to implement
  - directives used in an include file
```
cd /etc/nginx/includes
sudo vi wp_nginx_security_directives.conf
# Deny Access To Important WP Files
location = /wp-config.php { deny all; }
location = /wp-admin/install.php { deny all; }
location ~* /readme\.html$ { deny all; }
location ~* /readme\.txt$ { deny all; }
location ~* /licence\.txt$ { deny all; }
location ~* /license\.txt$ { deny all; }
location ~ ^/wp-admin/includes/ { deny all; }
location ~ ^/wp-includes/[^/]+\.php$ { deny all; }
location ~ ^/wp-includes/js/tinymce/langs/.+\.php$ { deny all; }
location ~ ^/wp-includes/theme-compat/ { deny all; }

# Disable PHP in Uploads, Plugins and Theme Directories
location ~* ^/wp\-content/uploads/.*\.(?:php[1-7]?|pht|phtml?|phps)$ { deny all; }
location ~* ^/wp\-content/plugins/.*\.(?:php[1-7]?|pht|phtml?|phps)$ { deny all; }
location ~* ^/wp\-content/themes/.*\.(?:php[1-7]?|pht|phtml?|phps)$ { deny all; }

# Filter Request Methods
if ( $request_method ~* ^(TRACE|DELETE|TRACK)$ ) { return 403; }

# Filter Suspicious Query Strings in the URL
set $susquery 0;
if ( $args ~* "\.\./" ) { set $susquery 1; }
if ( $args ~* "\.(bash|git|hg|log|svn|swp|cvs)" ) { set $susquery 1; }
if ( $args ~* "etc/passwd" ) { set $susquery 1; }
if ( $args ~* "boot\.ini" ) { set $susquery 1; }
if ( $args ~* "ftp:" ) { set $susquery 1; }
if ( $args ~* "(<|%3C)script(>|%3E)" ) { set $susquery 1; }
if ( $args ~* "mosConfig_[a-zA-Z_]{1,21}(=|%3D)" ) { set $susquery 1; }
if ( $args ~* "base64_decode\(" ) { set $susquery 1; }
if ( $args ~* "%24&x" ) { set $susquery 1; }
if ( $args ~* "127\.0" ) { set $susquery 1; }
if ( $args ~* "(globals|encode|loopback|request|insert|concat|union|declare)" ) { set $susquery 1; }
if ( $args ~* "(request|localhost)" ) { set $susquery 1; }
if ( $args ~* "%[01][0-9A-F]" ) { set $susquery 1; }
if ( $args ~ "^loggedout=true" ) { set $susquery 0; }
if ( $args ~ "^action=jetpack-sso" ) { set $susquery 0; }
if ( $args ~ "^action=rp" ) { set $susquery 0; }
if ( $http_cookie ~ "wordpress_logged_in_" ) { set $susquery 0; }
if ( $http_referer ~* "^https?://maps\.googleapis\.com/" ) { set $susquery 0; }
if ( $susquery = 1 ) { return 403; }

# BLOCK COMMON SQL INJECTIONS
set $block_sql_injections 0;
if ($query_string ~ "union.*select.*\(") { set $block_sql_injections 1; }
if ($query_string ~ "union.*all.*select.*") { set $block_sql_injections 1; }
if ($query_string ~ "concat.*\(") { set $block_sql_injections 1; }
if ($block_sql_injections = 1) { return 403; }

# BLOCK FILE INJECTIONS
set $block_file_injections 0;
if ($query_string ~ "[a-zA-Z0-9_]=http://") { set $block_file_injections 1; }
if ($query_string ~ "[a-zA-Z0-9_]=(\.\.//?)+") { set $block_file_injections 1; }
if ($query_string ~ "[a-zA-Z0-9_]=/([a-z0-9_.]//?)+") { set $block_file_injections 1; }
if ($block_file_injections = 1) { return 403; }

# BLOCK COMMON EXPLOITS
set $block_common_exploits 0;
if ($query_string ~ "(<|%3C).*script.*(>|%3E)") { set $block_common_exploits 1; }
if ($query_string ~ "GLOBALS(=|\[|\%[0-9A-Z]{0,2})") { set $block_common_exploits 1; }
if ($query_string ~ "_REQUEST(=|\[|\%[0-9A-Z]{0,2})") { set $block_common_exploits 1; }
if ($query_string ~ "proc/self/environ") { set $block_common_exploits 1; }
if ($query_string ~ "mosConfig_[a-zA-Z_]{1,21}(=|\%3D)") { set $block_common_exploits 1; }
if ($query_string ~ "base64_(en|de)code\(.*\)") { set $block_common_exploits 1; }
if ($block_common_exploits = 1) { return 403; }

# BLOCK SPAM
set $block_spam 0;
if ($query_string ~ "\b(ultram|unicauca|valium|viagra|vicodin|xanax|ypxaieo)\b") { set $block_spam 1; }
if ($query_string ~ "\b(erections|hoodia|huronriveracres|impotence|levitra|libido)\b") { set $block_spam 1; }
if ($query_string ~ "\b(ambien|blue\spill|cialis|cocaine|ejaculation|erectile)\b") { set $block_spam 1; }
if ($query_string ~ "\b(lipitor|phentermin|pro[sz]ac|sandyauer|tramadol|troyhamby)\b") { set $block_spam 1; }
if ($block_spam = 1) { return 403; }

# BLOCK USER AGENTS
set $block_user_agents 0;
if ($http_user_agent ~ "Indy Library") { set $block_user_agents 1; }
if ($http_user_agent ~ "libwww-perl") { set $block_user_agents 1; }
if ($http_user_agent ~ "GetRight") { set $block_user_agents 1; }
if ($http_user_agent ~ "GetWeb!") { set $block_user_agents 1; }
if ($http_user_agent ~ "Go!Zilla") { set $block_user_agents 1; }
if ($http_user_agent ~ "Download Demon") { set $block_user_agents 1; }
if ($http_user_agent ~ "Go-Ahead-Got-It") { set $block_user_agents 1; }
if ($http_user_agent ~ "TurnitinBot") { set $block_user_agents 1; }
if ($http_user_agent ~ "GrabNet") { set $block_user_agents 1; }
if ($http_user_agent ~ "dirbuster") { set $block_user_agents 1; }
if ($http_user_agent ~ "nikto") { set $block_user_agents 1; }
if ($http_user_agent ~ "SF") { set $block_user_agents 1; }
if ($http_user_agent ~ "sqlmap") { set $block_user_agents 1; }
if ($http_user_agent ~ "fimap") { set $block_user_agents 1; }
if ($http_user_agent ~ "nessus") { set $block_user_agents 1; }
if ($http_user_agent ~ "whatweb") { set $block_user_agents 1; }
if ($http_user_agent ~ "Openvas") { set $block_user_agents 1; }
if ($http_user_agent ~ "jbrofuzz") { set $block_user_agents 1; }
if ($http_user_agent ~ "libwhisker") { set $block_user_agents 1; }
if ($http_user_agent ~ "webshag") { set $block_user_agents 1; }
if ($http_user_agent ~ "Acunetix-Product") { set $block_user_agents 1; }
if ($http_user_agent ~ "Acunetix") { set $block_user_agents 1; }
if ($block_user_agents = 1) { return 403; }

cd /etc/nginx/sites-available/
sudo vi example.com
sudo nginx -t
sudo systemctl reload nginx
```

- stop brute force attack using nginx
- rate limiting
  - xmlrpc.php
  - wp-login.php
  - rate limiting exceeded
  - return a http 444 code
  - 444 nginx only response code
  - means the server will return no response
```
cd /etc/nginx/
sudo nano nginx.conf
##
# Rate Limiting
##
limit_req_zone $binary_remote_addr zone=wp:10m rate=30r/m;
cd /etc/nginx/includes/
sudo nano rate_limiting.conf

Contents:
location = /wp-login.php {
limit_req zone=wp nodelay;
limit_req_status 444;
include snippets/fastcgi-php.conf;
fastcgi_pass unix:/run/php/php8.1-fpm.sock;
include /etc/nginx/includes/fastcgi_optimize.conf;
}

location = /xmlrpc.php {
limit_req zone=wp nodelay;
limit_req_status 444;
include snippets/fastcgi-php.conf;
fastcgi_pass unix:/run/php/php8.1-fpm.sock;
include /etc/nginx/includes/fastcgi_optimize.conf;
}

# Rate Limiting Include
include /etc/nginx/includes/rate_limiting.conf;

Test configuration and then reload nginx
sudo nginx -t
sudo systemctl reload nginx

NGINX DDOS RATE LIMITING
cd /etc/nginx/
sudo nano nginx.conf
##
# Rate Limiting & Limit Requests
##
limit_req_zone $binary_remote_addr zone=wp:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=ip_address:10m rate=100r/s;
limit_req zone=ip_address nodelay;

cd /etc/fail2ban
sudo nano jail.local

Modify:
[nginx-limit-req]
port    = http,https
logpath = /var/log/nginx/error*.log
maxretry = 10
enabled = true

To enable, restart the f2b service.
sudo systemctl restart fail2ban

Test configuration and then reload nginx
sudo nginx -t
sudo systemctl reload nginx

Test rate limitinng:
wpscan --url https://<your_domain>/ --passwords passwords.txt
look at the logs
```

- hot linking protection
  - images being hot linked?
  - stealing your bandwidth
  - monthly server cost increases
  - cloudflare hotlinking protection
  - nginx hotlinking protection
- Cloudflare hotlinking protection
  - easy to configure
  - one-click and it's done
  - only implement after setting up
  - cloudflare as per the course
  - enable Scrap Shield > Hotlink Protection on your domain in cloudflare
- Nginx hotlinking protection
  - will not work when cloudflare is enabled
  - offers more config options at the expense of possible config issues
  - can be a slightly complex setup
  - will result in more server resource demands because cloudflare is disabled
Nginx DDOS Protection
    - ddos protection
      - stop small ddos attacks
      - needs to be stopped at ahigher level
      - enable cloudlflare or contact your host
      - enable the nginx-limit-req fail2ban jail
    - limit incoming requests to a value of real users
    - customizes to your sites requirements
    - limit the number of connections per single ip
```
NGINX DDOS RATE LIMITING
cd /etc/nginx/
sudo nano nginx.conf
##
# Rate Limiting & Limit Requests
##
limit_req_zone $binary_remote_addr zone=wp:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=ip_address:10m rate=100r/s;


cd sites-available/
sudo vi pristinehost.uk.conf
limit_req zone=ip_address nodelay;
```
- fail2ban nginx-limit-req jail
  - it can break the site
```
cd /etc/fail2ban
sudo vi jail.local

Modify:
[nginx-limit-req]
port    = http,https
logpath = /var/log/nginx/error*.log
maxretry = 10
enabled = true

To enable, restart the f2b service.
sudo systemctl restart fail2ban

Test configuration and then reload nginx
sudo nginx -t
sudo systemctl reload nginx
```
nginx limit_req directive
- not recommended to enable "site" wide
- can interfere with site functionality
- can lead to breaking the site
- can ban legitimate site users
- enable only for xmlrpc and wp-login protection

- web app firewall
  - waf will intercept requests and either
  - allow or deny the request
  - based on rules
  - best wp waf is Ninja firewall
  - easy to set up
  - https://wordpress.org/plugins/ninjafirewall/
```
cd /var/www/<your_domain>
sudo chmod 775 public_html
install ninja firewall plugin
sudo ./ownership_permissions.sh
after installation and settings
press enter
```

### Optimizing WP
- server side
  - optimizing os
  - optimizing web server
  - configure php-fpm
  - serve-side caching
  - set wp max memory
  - replace wp cron with real cron

- server side optimization
  - caching
  - configure php-fpm
  - replace wp cron with real cron 
    - wp cron system is used to schedule tasks that run at intervals and on every page load
    - slow down the site
    - improve performance and stability of site
    - replace this with server-side cron
```
cd /var/www/<your_domain>/public_html/
sudo vi wp-config.php
/** DISABLE WP-CRON */
define('DISABLE_WP_CRON', true );

fpmr
crontab -e
*/15 * * * * wget -q -O - https://example.com/wp-cron.php?doing_wp_cron >/dev/null 2>&1
crontab -l
```

- application side:
  - caching
  - optimize policy
  - optimize db
  - combine minify css and js
  - post revisions policy
    - https://wordpress.org/support/article/revisions/
    - revisions can result in a bloated db
    - each revision means additional row is added to the db
    - consider if it's needed
    - if not, disable revisions completely
```
https://wordpress.org/support/article/revisions/
define('WP_POST_REVISIONS', false);
```
![request-process.png](diagrams%2Frequest-process.png)

- CACHING
  - pages caching 
    - on most pages contest seldom changes
    - why query dba nd use php?
    - to build the page on request?
    - the solution is to pre-build the page
    - clients are served these pre-built pages
    - therefore bypassing php and the database
  - object caching 
    - stores db query results
    - the cached object will be served from the cache (RAM) instead of querying the db
    - for object caching to be effective
    - the db queries need to be cached
    - persistently between page loads
    - wp has built in object caching
    - enabled by default
    - only stores for a single page load
    - not a persistent object cache
    - persistent object caching will ease the load on db
    - deliver queries faster
    - reduce demand for resources
    - improved browsing experience for logged-in users
    - to enable persistent object caching
    - we will use redis
      - redis has limited amount of memory
      - caching badly coded plugins attempt to store huge amounts of data in db
      - redis will run out of memory
      - server will slow down
  - opcode caching 
    - for php code to execute, the php compiler has to compile the code first and generate executable code
    - for the server to execute opcode caches the already compiled code
    - installed and configured on the server opcache
```
# PHP Files
count number of php files
cd /var/www
find . -type f -print | grep php | wc -l

cd /etc/php/8.1/fpm/
sudo vi php.ini

cd /etc/nginx
sudo vi nginx.conf

Setup the site completely first.
If php files are less than 10000, don't make any changes.
If yes, set to 20000 opcache.max_accelerated_files=20000
We will add the relevant directives to the http context first.
```
  - browser caching 
    - /etc/nginx/includes/browser_caching.conf;
![caching.png](diagrams%2Fcaching.png)


Static and Dynamic site
- static
  - content seldom changes
  - informational type site
  - no comments
  - contact form
  - very little interaction with visitors
  - link to sites social media pages
- dynamic
  - content changes frequently
  - any form of ecommerce
  - forums
  - active comment section
  - links to sites social media pages

Caching Policy
- implementing caching
  - caching method depends on the type of wp site 
  - static or dynamic
- static
  - page caching
  - server side page caching
  - nginx fastcgi
    - brilliant performance
    - additional performance plugins are needed
    - easy to set up
    - setting cache exclusions can be complex
    - use to configure only page caching
    - additional plugin needed for object caching
  - wp caching plugin
  - w3tc
    - all in one performance solution
    - no additional plugin needed
    - free version suitable for almost all sites
    - little complex to setup
    - can take time to configure
    - used to configure both page and object caching
- dynamic
  - page caching 
  - wp caching plugin
  - w3tc
  - object caching
  - redis

```
Navigate to the comment:
/* That’s all, stop editing and just above the comment add the directive to disable WP CRON:

define('DISABLE_WP_CRON', true);

Close nano, saving the changes, then I recommend you resstart the php-fpm process to clear the opcache.
sudo systemctl restart php8.1-fpm

Now we need to create the server cron. This job will run as your non root user and not root.
crontab -e
JOB:
*/15 * * * * wget -q -O - https://example.com/wp-cron.php?doing_wp_cron >/dev/null 2>&1

It's easy to disable revisions, open your site's wp-config.php file and add the following above the comment: /* That’s all Stop editing…
define('WP_POST_REVISIONS', false);

# PHP Files
cd /var/www
find . -type f -print | grep php | wc -l

sudo nano /etc/php/8.1/fpm/
sudo vi php.ini

cd /etc/nginx
sudo vi nginx.conf

We will add the relevant directives to the http context first

HTTP CONTEXT

Scroll to just above the comment:
# Virtual Host Configs

##
# FASTCGI CACHING
##
# fastcgi_cache_path directive - PATH & NAME must be unique for each site
# Add a new fastcgi_cache_path for each site and give a new keys_zone name
fastcgi_cache_path /var/run/SITE levels=1:2 keys_zone=NAME:100m inactive=60m;

# applied to all sites
fastcgi_cache_key "$scheme$request_method$host$request_uri";
fastcgi_cache_use_stale error timeout invalid_header http_500;
fastcgi_ignore_headers Cache-Control Expires Set-Cookie;


cd sites-available/
sudo vi

location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    include /etc/nginx/include_files/fastcgi_optimize.conf;
    # fastcgi caching directives
    fastcgi_cache_bypass $skip_cache;
    fastcgi_no_cache $skip_cache;
    fastcgi_cache NAME;
    fastcgi_cache_valid 60m;
}

ngt
nginx: [emerg] unknown "skip_cache" variable
nginx: configuration file /etc/nginx/nginx.conf test failed

cd ..includes/
sudo vi fastcgi_cache_exclusions.conf


DIRECTIVES
fastcgi_cache_bypass $skip_cache;
fastcgi_no_cache $skip_cache;
fastcgi_cache NAME;
fastcgi_cache_valid 60m;

cd /etc/nginx/includes/
sudo nano fastcgi_cache_exclusions.conf

# NGINX SKIP CACHE INCLUDE FILE
set $skip_cache 0;

# POST requests and urls with a query string should always go to PHP
if ($request_method = POST) {
    set $skip_cache 1;
}

if ($query_string != "") {
    set $skip_cache 1;
}   

# Don't cache uris containing the following segments
if ($request_uri ~* "/wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml") {
    set $skip_cache 1;
} 

# Don't use the cache for logged in users or recent commenters
if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") {
    set $skip_cache 1;
}

cd /etc/nginx/sites-available
sudo vi example.com.conf

Add the include directive underneath the closing curly bracket of the location context that contains the try_files directive.
include /etc/nginx/includes/fastcgi_cache_exclusions.conf;


cd /etc/nginx/sites-available
sudo vi example.com.conf
include /etc/nginx/includes/http_headers.conf;
add_header X-FastCGI-Cache $upstream_cache_status;

As always, test the nginx syntax and then reload nginx to enable the change in configuration.
sudo nginx -t
sudo systemctl reload nginx

curl -I https://example.com
curl -I https://www.example.com

Install nginx helper plugin
cd /var/www/example.com/public_html
sudo chmod 664 wp-config
cd
sudo ./ownership_permissions.sh
sudo vi /var/www/pristinehost.uk/public_html/wp-config.php
define('RT_WP_NGINX_HELPER_CACHE_PATH','/var/run/PATH/');

Close vi, saving the changes, then restart the php-fpm process
sudo systemctl restart php8.1-fpm

Under the index directive add the location block that will allow for selective purging of the cache:
index index.php;
location ~ /purge(/.*) {
    fastcgi_cache_purge NAME "$scheme$request_method$host$1";
}
sudo nginx -t
sudo systemctl reload nginx

cd /var/log/nginx
sudo cat error_<your_domain>.log 

cd /etc/nginx
sudo vi nginx.conf
comment out:
#limit_req_zone $binary_remote_addr zone=ip_address:10m rate=100r/s;

cd /etc/nginx/sites-available
sudo vi <your_domain>.conf
comment out:
#limit_req zone=ip_address nodelay;

cd /etc/fail2ban
sudo vi jail.conf

Modify:
[nginx-limit-req]
port    = http,https
logpath = /var/log/nginx/error*.log
maxretry = 10
enabled = false

To enable, restart the f2b service.
sudo systemctl restart fail2ban
```
WT3C and redis
```
Install W3 total cache plugin
Comment out all fastcgi nginx changes in nginx.conf, wp-config.php and <your_domain>.conf
Before activating:
sudo ./ownership_permissions.sh

# W3TC
cd /var/www/example.com/public_html/
sudo touch nginx.conf
sudo chown www-data:www-data nginx.conf

ls
sudo chown $USER:www-data nginx.conf
sudo chmod 664 nginx.conf wp-config.php

Add directive to wp security file that blocks any attempts to access the file we created.
cd /etc/nginx/includes/

sudo nano wp_nginx_security_directives.conf

Add the following directive to the wp_security file
location = /nginx.conf { deny all; }

cd /var/www/example.com/public_html/
ls -l

Permissions:
cd /var/www/example.com/public_html/
sudo chmod 664 nginx.conf wp-config.php

The permissions on wp-config.php can be changed back to 644 after we activate w3tc using the WP dashboard.
sudo chmod 644 /var/www/site.com/public_html/wp-config.php

cd /etc/nginx/includes/
sudo vi w3tc_cache_exclusions.conf

# ---------------------
# W3 TOTAL CACHE EXCLUDES FILE
# ---------------------
set $cache_uri $request_uri;

# POST requests and urls with a query string should always go to PHP
if ($request_method = POST) {
        set $cache_uri 'null cache';
}   

if ($query_string != "") {
        set $cache_uri 'null cache';
}   

# Don't cache uris containing the following segments
if ($request_uri ~* "(/wp-admin/|/xmlrpc.php|/wp-(app|cron|login|register|mail).php|wp-.*.php|/feed/|index.php|wp-comments-popup.php|wp-links-opml.php|wp-locations.php|sitemap(_index)?.xml|[a-z0-9_-]+-sitemap([0-9]+)?.xml)") {
        set $cache_uri 'null cache';
}   

# Don't use the cache for logged in users or recent commenters
if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_logged_in") {
        set $cache_uri 'null cache';
}

# Use cached or actual file if they exists, otherwise pass request to WordPress
location / {
        try_files /wp-content/w3tc/pgcache/$cache_uri/_index.html $uri $uri/ /index.php?$args;
}

cd /etc/nginx/sites-available/
sudo vi example.com.conf

#location / {

#    try_files $uri $uri/ /index.php$is_args$args;

#}

include /etc/nginx/includes/w3tc_exclusions.conf;
include /var/www/example.com/public_html/nginx.conf;

supd
sudo apt install php8.1-tidy
fpmr

sudo nginx -t
sudo systemctl reload nginx
sudo apt install php8.1-tidy

# REDIS
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt-get update
sudo apt install redis-server php8.1-redis

Check the status of redis:
sudo systemctl status redis-server

Check the redis log for any errors:
sudo cat /var/log/redis/redis-server.log

Issues:
WARNING overcommit_memory is set to 0! Background save may fail under low memory condition.

sudo nano /etc/sysctl.conf
vm.overcommit_memory = 1
sudo sysctl -p

sudo systemctl status redis-server
sudo cat /var/log/redis/redis-server.log

cd /etc/redis
sudo nano redis.conf

maxmemory 256mb
maxmemory-policy allkeys-lru
sudo systemctl restart redis-server
cd /var/www/site.com/public_html/
sudo nano wp-config.php

define( 'WP_CACHE_KEY_SALT', 'example.com' );

redis-cli monitor
```

PHP-FPM
- configure php-fpm
- important to set pm.max_children directive value correctly
- if not set correctly, it may result in your server crashing
- too low, site will slow down, too high and your site will crash
- all sites are different
  - depends on memory used by each child process
  - memory used by each child process
  - will vary due to theme and plugins being used
- recalculate the memory used by each child process
- after completing your site setup
- adding, removing or upgrading themes and plugins
- weekly maintenance task
- set the directive
- pm.max_children
- different for each server and site
- calculate the memory
- used by each child process
- set the directive according to this value
- configure pm
- how it controls the max children directive

## FPM Types
- on demand
  - child processes are spawn on-demand
  - suitable for all sites 
  - no wasted resources
  - calculate the max memory usage
  - for a single child process
  - set the method on demand
    - set the following directives: 
      - max children
      - process idle timeout
      - max requests
- static
  - number of child processes are fixed
  - excellent for busy sites
  - processes are ready to serve requests
  - without needing to be spawned
  - calculate the max memory usage
  - for a single child process
  - set the method to static
    - set the following directives:
      - max children
- dynamic
  - number of child processes is set dynamically
```
PHP-FPM
Calculate memory used by each child processes: (on-demand and static)
ps --no-headers -o "rss,cmd" -C php-fpm8.1 | awk '{ sum+=$1 } END { printf ("%d%s\n", sum/NR/1024,"M") }'
44M
Take what's available and divide to 44
500M/44M = 11.36
production server should have a minimum of 2GB of RAM

ONDEMAND:
cd /etc/php/8.1/fpm/pool.d/
ls
sudo cp www.conf www.conf.bak
sudo vi www.conf
pm = ondemand
pm.max_children = 7
pm.process_idle_timeout = 10s;
pm.max_requests = 500

fpmr
sudo systemctl restart php8.1-fpm
ls /var/log/
sudo cat php8.1-fpm.log

Check the log file for warning.
sudo grep max_children /var/log/php8.1-fpm.log
Grep will display the following line if it occurs in your log file
WARNING: [pool www] server reached max_children setting (25), consider raising it

CLOUDFLARE
https://www.cloudflare.com/ips-v4
https://www.cloudflare.com/ips-v6

cd /etc/nginx/includes
sudo nano cloudflare_ip_list.conf

# Last updated 17 July 2022
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header CF-Connecting-IP;

cd /etc/nginx/sites-available/
sudo nano example.com.conf

Addition:
include /etc/nginx/includes/cloudflare_ip_list.conf;
Close nano saving the changes.

As always, test the syntax and then reload nginx
sudo nginx -t
sudo systemctl reload nginx
```
## Support

<a href="https://www.buymeacoffee.com/pristineweb" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/purple_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

## License

MIT
https://pristinehost.uk

---

> GitHub [@william](https://github.com/william251082)


### Extras:
REMOVE A SWAP FILE

Deactivate the swap using the following command:
```sudo swapoff -v /swapfile```

Open the fstab file using nano:
```sudo nano /etc/fstab```

Remove the swap file entry from the /etc/fstab file.
```/swapfile swap swap defaults 0 0```

Delete the swapfile:
```sudo rm /swapfile```

Reboot the server
```sudo reboot```
ONE SWAP FILE REMOVED




