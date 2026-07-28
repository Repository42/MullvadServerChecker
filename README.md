# Mullvad server fraud score checker
Helps you find clean ip addresses so you dont get discriminated against.

(if you run this too often scamalytics may rate limit you.)

## NEW UPDATE (28/07/2026)
added options for abuseipdb (although is less accurate)

just add your api key to the `auth_abuseipdb.json` file under the key `key`

then either set the `MULLVAD_CHECKER_AUTH` env in your .bashrc or specify the file with `-c auth_abuseipdb.json`

## Example running
![programExample](https://github.com/Repository42/MullvadServerChecker/blob/9359fa58abe8dc7e575f84e00d7a2b0957bb2062/programExample.png)

## Example TSV file
an example tsv file of information can be found [here](https://Repository42/MullvadServerChecker/servers_28.07.2026.tsv)
