# Mullvad server ip score checker
Helps you find clean ip addresses so you don't get discriminated against.

## NEW UPDATE (28/07/2026)
added options for abuseipdb (although is less accurate)

better code / file structuring

faster requests library (wreq)

## Install
just git clone this project: `git clone https://github.com/Repository42/MullvadServerChecker.git`

install requirements: `python -m pip install -r requirements.txt`

## Usage 
set `MULLVAD_CHECKER_AUTH` in your .bashrc or specify the file with `-c AUTH_FILE_HERE.json`

and then run the script: `python main.py`

## AbuseIPDB
sign up to abuseipdb.com and create a free account

a free account gives you a daily limit of 1000 requests which is enough to check all 500ish mullvad servers once a day

add your api key to the `auth_abuseipdb.json` file under the `key` key

there is no rps limit so you don't need to supply `--threads`

## Scamalytics
i recommend adding `--threads 20` if you are using the standard scamalytics api so you don't trip the limit rate.

i also recommend adding cookies from scamalytics.com such as `cf_clearance` so you don't trip cloudflare.

## Example running
![programExample](https://github.com/Repository42/MullvadServerChecker/blob/9359fa58abe8dc7e575f84e00d7a2b0957bb2062/programExample.png)

## Example TSV file
an example tsv file of information can be found [here](https://github.com/Repository42/MullvadServerChecker/blob/main/servers_28.07.2026.tsv)
