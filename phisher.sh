#!/usr/bin/env bash
# Version         : 1.0
# Created date    : 26/10/2022
# Last update     : 
# Author          : fyoozr
# Description     : The Phishing Environment builder
# Note            : Tested on Ubuntu 22.04.1 LTS

### Colors
red=`tput setaf 1`;
green=`tput setaf 2`;
yellow=`tput setaf 3`;
blue=`tput setaf 4`;
magenta=`tput setaf 5`;
cyan=`tput setaf 6`;
bold=`tput bold`;
clear=`tput sgr0`;

banner() {
cat <<EOF
${blue}${bold}
___       ___     __          __        ___  __  
 |  |__| |__     |__) |__| | /__  |__| |__  |__)  
 |  |  | |___    |    |  | | .__/ |  | |___ |  \ 
                                                                                                          
${clear}
EOF

}

usage() {
  local ec=0

  if [ $# -ge 2 ] ; then
    ec="$1" ; shift
    printf "%s\n\n" "$*" >&2
  fi

  banner
  cat <<EOF

A quick Bash script to install GoPhish server with Postfix, OpenDKIM and Let's Encrypt SSL. 

${bold}Usage: ${blue}./$(basename $0) [-d <domain name> ] [-c] [-h]${clear}

One shot to set up:
  - Postfix email server
  - OpenDKIM settings
  - Gophish Server
  - SSL Cert for Phishing Domain (LetsEncrypt)

Options:
  -d <domain name>      SSL cert for phishing domain
  -c 			Cleanup for a fresh install
  -h              	This help menu

Examples:
  ./$(basename $0) -d <domain name>			Configure Posftix + DKIM/DMARC/SPF + Gophish + SSL


EOF

exit $ec
 
}

### Exit
exit_error() {
	usage
	exit 1
}

### Initial Update & Dependency Check
dependencyCheck() {
	### Update Sources
	echo "${blue}${bold}[*] Updating source lists...${clear}"
	apt-get update -y >/dev/null 2>&1	


	### Checking/Installing unzip
	unzip=$(which unzip)

	if [[ $unzip ]];
	then
		echo "${green}${bold}[+] Unzip already installed${clear}"
	else
		echo "${blue}${bold}[*] Installing unzip...${clear}"
		apt-get install unzip -y >/dev/null 2>&1
	fi

	### Checking/Installing go
        gocheck=$(which go)

        if [[ $gocheck ]];
        then
                echo "${green}${bold}[+] Golang already installed${clear}"
        else
                echo "${blue}${bold}[*] Installing Golang...${clear}"
                apt-get install golang -y >/dev/null 2>&1
                export CGO_CFLAGS="-g -O2 -Wno-return-local-addr"

                #Download Latest Go
				#printf "Checking latest Go version...\n";
				#LATEST_GO_VERSION="go1.15.15" #"$(curl --silent https://go.dev/VERSION?m=text)";
				#LATEST_GO_DOWNLOAD_URL="https://golang.org/dl/${LATEST_GO_VERSION}.linux-amd64.tar.gz "
				
				#printf "Downloading ${LATEST_GO_DOWNLOAD_URL}\n\n";
				#curl -OJ -L --progress-bar https://golang.org/dl/${LATEST_GO_VERSION}.linux-amd64.tar.gz
				
				# Remove Old Go
				#sudo rm -rf /usr/local/go
				
				# Install new Go
				#sudo tar -C /usr/local -xzf ${LATEST_GO_VERSION}.linux-amd64.tar.gz
				#echo "Create the skeleton for your local users go directory"
				#mkdir -p ~/go/{bin,pkg,src}
				#echo "Setting up GOPATH"
				#echo "export GOPATH=~/go" >> ~/.profile && source ~/.profile
				#echo "${green}${bold}[+] Setting PATH to include golang binaries${clear}"
				#echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
				#source ~/.profile
				#export CGO_CFLAGS="-g -O2 -Wno-return-local-addr"
				
				# Remove Download
				#rm ${LATEST_GO_VERSION}.linux-amd64.tar.gz
				
				#unset LATEST_GO_VERSION
				#unset LATEST_GO_DOWNLOAD_URL
				
				# Print Go Version
				printf "${cyan}${bold}You are ready to Go!\n${clear}";
				go version
        fi
	
	### Checking/Installing git
        gitcheck=$(which git)

        if [[ $gitcheck ]];
        then
                echo "${green}${bold}[+] Git already installed${clear}"
        else
                echo "${blue}${bold}[*] Installing Git...${clear}"
                apt-get install git -y >/dev/null 2>&1
        fi

    ### Checking/Installing Certbot
    	certbotcheck=$(which certbot)

        if [[ $certbotcheck ]];
        then
                echo "${green}${bold}[+] Certbot already installed${clear}"
        else
                echo "${blue}${bold}[*] Installing Certbot...${clear}"
                apt-get install certbot -y >/dev/null 2>&1
        fi

    ### Checking/Installing Postfix
    	postfixcheck=$(which postfix)

        if [[ $postfixcheck ]];
        then
                echo "${green}${bold}[+] Postfix already installed${clear}"
        else
                echo "${blue}${bold}[*] Installing Postfix...${clear}"
                debconf-set-selections <<< "postfix postfix/mailname string $domain"
				debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
                apt-get install postfix -y >/dev/null 2>&1
        fi

    ### Checking/Installing OpenDKIM
    	opendkimcheck=$(which opendkim)

        if [[ $opendkimcheck ]];
        then
                echo "${green}${bold}[+] Opendkim already installed${clear}"
        else
                echo "${blue}${bold}[*] Installing Opendkim...${clear}"
                apt-get install opendkim opendkim-tools -y >/dev/null 2>&1
        fi

     ### Checking/Installing fuser
    	fusercheck=$(which fuser)

        if [[ $fusercheck ]];
        then
                echo "${green}${bold}[+] Fuser already installed${clear}"
        else
                echo "${blue}${bold}[*] Installing fuser...${clear}"
                apt-get install psmisc -y >/dev/null 2>&1
        fi
}

### Setup Gophish
setupGophish() {
	### Cleaning Port 80
	fuser -k -s -n tcp 80

	### Deleting Previous Gophish Source (*Need to be removed to update new rid)
	rm -rf /root/go/src/github.com/gophish >/dev/null 2>&1 &&

	### Installing GoPhish
    echo "${blue}${bold}[*] Downloading gophish (x64)...${clear}"
    mkdir -p /root/go &&
	export GOPATH=/root/go &&
	#source ~/.profile &&
	git clone https://github.com/gophish/gophish.git /root/go/src/github.com/gophish/gophish/ &&
	cd /root/go/src/github.com/gophish/gophish/; go build

	echo "${blue}${bold}[*] Creating a gophish folder: /opt/gophish${clear}"
    mkdir -p /opt/gophish &&

 	# Stripping X-Gophish header
	sed -i 's/X-Gophish-Contact/X-Contact/g' $GOPATH/src/github.com/gophish/gophish/models/email_request_test.go &&
	sed -i 's/X-Gophish-Contact/X-Contact/g' $GOPATH/src/github.com/gophish/gophish/models/maillog.go &&
	sed -i 's/X-Gophish-Contact/X-Contact/g' $GOPATH/src/github.com/gophish/gophish/models/maillog_test.go &&
	sed -i 's/X-Gophish-Contact/X-Contact/g' $GOPATH/src/github.com/gophish/gophish/models/email_request.go &&

	# Stripping X-Gophish-Signature header
	sed -i 's/X-Gophish-Signature/X-Signature/g' $GOPATH/src/github.com/gophish/gophish/webhook/webhook.go &&

	# Changing server name
	sed -i 's/const ServerName = "gophish"/const ServerName = "mailer"/' $GOPATH/src/github.com/gophish/gophish/config/config.go &&

	# Changing rid value
	sed -i 's/const RecipientParameter = "rid"/const RecipientParameter = "key"/g' $GOPATH/src/github.com/gophish/gophish/models/campaign.go &&

	go build $GOPATH/src/github.com/gophish/gophish &&
	mv ./gophish /opt/gophish/gophish &&
	cp -R $GOPATH/src/github.com/gophish/gophish/* /opt/gophish &&
	sed -i 's!127.0.0.1!0.0.0.0!g' /opt/gophish/config.json &&

    echo "${blue}${bold}[*] Creating a gophish log folder: /var/log/gophish${clear}"
    mkdir -p /var/log/gophish &&

	### Start Script Setup	
	echo "#!/bin/bash
# /etc/init.d/gophish
# Description: Initialization file: service gophish {start|stop|status} 
# Config:/opt/gophish/config.json

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() 
{
echo 'Starting '\${processName}'...'
cd \${appDirectory}
nohup ./\$process >>\$logfile 2>>\$errfile &
sleep 1
}

stop() 
{
echo 'Stopping '\${processName}'...'
pid=\$(/usr/bin/pidof \${process})
kill \${pid}
sleep 1
}

status() 
{
pid=\$(/usr/bin/pidof \{process})
if [[ "\$pid" != \"\" ]]; then
echo \${processName}' is running...'
else
echo \${processName}' is not running...'
fi
}

case \$1 in
start|stop|status) "\$1" ;;
esac
" > /etc/init.d/gophish &&
	chmod +x /etc/init.d/gophish &&
	update-rc.d gophish defaults
}

### Setup DKIM
setupDKIM() {
	# Create an OpenDKIM key in the proper place with proper permissions.
	echo 'Generating OpenDKIM keys...'
	ipAddr=$(curl ifconfig.io 2>/dev/null)
	mkdir -p "/etc/opendkim/keys/$domain"
	opendkim-genkey -D "/etc/opendkim/keys/$domain" -d "$domain" -s "dkim"
	chown -R opendkim:opendkim /etc/opendkim/*

	# Generate the OpenDKIM info:
	echo 'Configuring OpenDKIM...'
	grep -q "$domain" /etc/opendkim/KeyTable 2>/dev/null ||
	echo "dkim._domainkey.$domain $domain:dkim:/etc/opendkim/keys/$domain/dkim.private" >> /etc/opendkim/KeyTable

	grep -q "$domain" /etc/opendkim/SigningTable 2>/dev/null ||
	echo "*@$domain dkim._domainkey.$domain" >> /etc/opendkim/SigningTable

	grep -q "*.$domain" /etc/opendkim/TrustedHosts 2>/dev/null ||
	echo "127.0.0.1
localhost
$ipAddr
*.$domain" >> /etc/opendkim/TrustedHosts

	# ...and source it from opendkim.conf
	grep -q '^KeyTable' /etc/opendkim.conf 2>/dev/null || echo 'KeyTable		/etc/opendkim/KeyTable
SigningTable		refile:/etc/opendkim/SigningTable
InternalHosts		refile:/etc/opendkim/TrustedHosts
ExternalIgnoreList	refile:/etc/opendkim/TrustedHosts' >> /etc/opendkim.conf

	sed -i '/^#Canonicalization/s/simple/relaxed\/simple/' /etc/opendkim.conf
	sed -i '/^#Canonicalization/s/^#//' /etc/opendkim.conf
	sed -i '/^#Mode/s/^#//' /etc/opendkim.conf

	sed -i '/Socket/s/^#*/#/' /etc/opendkim.conf
	grep -q '^Socket\s*inet:8892@localhost' /etc/opendkim.conf || echo 'Socket			inet:8892@localhost' >> /etc/opendkim.conf

	# OpenDKIM daemon settings, removing previously activated socket.
	sed -i '/^SOCKET/d' /etc/default/opendkim && echo "SOCKET=inet:8892@localhost" >> /etc/default/opendkim

	# Here we add Postfix setting to postconf needed for working with OpenDKIM
	echo 'Configuring Postfix with OpenDKIM settings...'
	myIp=$(echo $ipAddr | sed 's/[^.]*$/0\/24/')
	postconf -e 'mynetworks = '$myIp', 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128'
	postconf -e 'smtpd_sasl_security_options = noanonymous, noplaintext'
	postconf -e 'smtpd_sasl_tls_security_options = noanonymous'
	postconf -e 'mydomain = '$domain
	postconf -e 'myorigin = $mydomain'
	#postconf -e 'mydestination = $mydomain, localhost.$mydomain, localhost.localdomain, localhost'
	postconf -e 'milter_default_action = accept'
	postconf -e 'milter_protocol = 2'
	postconf -e 'smtpd_milters = inet:localhost:8892'
	postconf -e 'non_smtpd_milters = $smtpd_milters'
	postconf -e 'smtpd_helo_required = yes'
	postconf -e 'smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname'
	postconf -e 'smtpd_sender_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_sender_login_mismatch, reject_unknown_reverse_client_hostname, reject_unknown_sender_domain'

	# Restart services
	service postfix restart 2>/dev/null &&
	service opendkim restart 2>/dev/null &&

	# Write out DKIM for Domain
	pval="$(tr -d '\n' <"/etc/opendkim/keys/$domain/dkim.txt" | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o 'p=.*')"
	dkimentry="dkim._domainkey.$domain TXT v=DKIM1; k=rsa; $pval"
	dmarcentry="_dmarc.$domain  TXT v=DMARC1; p=reject; rua=mailto:dmarc@$domain; fo=1"
	spfentry="$domain TXT v=spf1 mx a:$domain -all"

	echo "$dkimentry
	$dmarcentry
	$spfentry" > "$HOME/dns_emailwizard"

	printf "\033[31m
	 _   _
	| \ | | _____      ___
	|  \| |/ _ \ \ /\ / (_)
	| |\  | (_) \ V  V / _
	|_| \_|\___/ \_/\_/ (_)\033[0m
	
	Add these three records to your DNS TXT records on either your registrar's site
	or your DNS server:
	\033[32m
	DKIM: $dkimentry
	
	DMARC: $dmarcentry
	
	SPF: $spfentry
	\033[0m"
}

### Setup SSL Cert
letsEncrypt() {
	### Clearing Port 80
	fuser -k -s -n tcp 80 
	service gophish stop 2>/dev/null
	
	### Installing certbot-auto
	#echo "${blue}${bold}[*] Installing certbot...${clear}" 
	#wget https://dl.eff.org/certbot-auto -qq
	#chmod a+x certbot-auto
	#apt-get install certbot -y >/dev/null 2>&1

	### Installing SSL Cert	
	echo "${blue}${bold}[*] Installing SSL Cert for $domain...${clear}"

	### Manual
	#./certbot-auto certonly -d $domain --manual --preferred-challenges dns -m info@$domain --agree-tos && 
	### Auto
	#certbot certonly --non-interactive --agree-tos --email info@$domain --standalone --preferred-challenges http -d $domain &&
	### Wildcard certificate
	certbot certonly --manual --agree-tos --email info@$domain --preferred-challenges dns -d *.$domain &&

	echo "${blue}${bold}[*] Configuring New SSL cert for $domain...${clear}" &&
	cp /etc/letsencrypt/live/$domain/privkey.pem /opt/gophish/domain.key &&
	cp /etc/letsencrypt/live/$domain/fullchain.pem /opt/gophish/domain.crt &&
	sed -i 's!false!true!g' /opt/gophish/config.json &&
	sed -i 's!:80!:443!g' /opt/gophish/config.json &&
	sed -i 's!:3333!:44390!g' /opt/gophish/config.json &&
	sed -i 's!example.crt!domain.crt!g' /opt/gophish/config.json &&
	sed -i 's!example.key!domain.key!g' /opt/gophish/config.json &&
	sed -i 's!gophish_admin.crt!domain.crt!g' /opt/gophish/config.json &&
	sed -i 's!gophish_admin.key!domain.key!g' /opt/gophish/config.json &&
	mkdir -p /opt/gophish/static/endpoint &&
	printf "User-agent: *\nDisallow: /" > /opt/gophish/static/endpoint/robots.txt &&
	echo "${green}${bold}[+] Check if the cert is correctly installed: https://$domain/robots.txt${clear}"
}

gophishStart() {
	service=$(ls /etc/init.d/gophish 2>/dev/null)

	if [[ $service ]];
	then
		sleep 1
		service gophish restart &&
		#ipAddr=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1)
		#ipAddr=$(curl ifconfig.io 2>/dev/null)
		pass=$(cat /var/log/gophish/gophish.error | grep 'Please login with' | cut -d '"' -f 4 | cut -d ' ' -f 10 | tail -n 1)
		echo "${green}${bold}[+] Gophish Started: https://$ipAddr:44390 - [Login] Username: admin, Temporary Password: $pass${clear}"
	else
		exit 1
	fi
}

cleanUp() {
	echo "${green}${bold}Cleaning...1...2...3...${clear}"
	service gophish stop 2>/dev/null
	service postfix stop 2>/dev/null
	service opendkim stop 2>/dev/null
	apt-get purge postfix opendkim opendkim-tools golang certbot -y
	rm -rf /root/go 2>/dev/null
	rm certbot-auto* 2>/dev/null
	rm -rf /opt/gophish 2>/dev/null
	rm /etc/init.d/gophish 2>/dev/null
	rm /etc/letsencrypt/keys/* 2>/dev/null
	rm /etc/letsencrypt/csr/* 2>/dev/null
	rm -rf /etc/letsencrypt/archive/* 2>/dev/null
	rm -rf /etc/letsencrypt/live/* 2>/dev/null
	rm -rf /etc/letsencrypt/renewal/* 2>/dev/null
	rm -rf /etc/opendkim/ 2>/dev/null
	rm dns_emailwizard 2>/dev/null
	apt-get autoremove -y
	echo "${green}${bold}[+] Done!${clear}"
}

domain=''

while getopts ":d:ch" opt; do
	case "${opt}" in
		d)
			banner
			domain=${OPTARG}
			dependencyCheck
			setupGophish  
			setupDKIM
			letsEncrypt && 
			gophishStart ;;
		c)
			cleanUp ;;
		h) 
			exit_error ;;
		:) 
			echo "${red}${bold}[-] Error: -${OPTARG} requires an argument (e.g., -d example.com)${clear}" 1>&2
			exit 1;;
	esac
done

if [[ $# -eq 0 ]];
then
	exit_error
fi
