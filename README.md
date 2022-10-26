# The Phisher
A quick Bash script to build environment for phishing assesment with GoPhish, Postfix, OpenDKIM and Let's Encrypt SSL. 

Table of contents
=================

<!--ts-->
   * [Installation](#installation)
   * [Usage](#usage)
<!--te-->

## Installation

```
git clone https://github.com/fyoozr/phisher.git
cd phisher
chmod +x phisher.sh
```

## Usage

This script will help you automate installing + configuring your email server and phishing domain with SSL certificate using [Certbot](https://github.com/certbot/certbot).

```
./phisher.sh -h

___       ___     __          __        ___  __
 |  |__| |__     |__) |__| | /__  |__| |__  |__)
 |  |  | |___    |    |  | | .__/ |  | |___ |  \



A quick Bash script to install GoPhish server with Postfix, OpenDKIM and Let's Encrypt SSL.

Usage: ./phisher.sh [-d <domain name> ] [-c] [-h]

One shot to set up:
  - Postfix email server
  - OpenDKIM settings
  - Gophish Server
  - SSL Cert for Phishing Domain (LetsEncrypt)

Options:
  -d <domain name> SSL cert for phishing domain
  -c Cleanup for a fresh install
  -h This help menu

Examples:
  ./phisher.sh -d <domain name>			Configure Posftix + DKIM + Gopshish + SSL
  ```
