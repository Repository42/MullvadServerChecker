# Mullvad server fraud score checker
Helps you find clean ip addresses so you dont get discriminated against by waf's

(if you run this too often scamalytics will rate limit you...)
## Usage
```
root@debian:~/mullvad$ ./main.py
Checking 660 servers.
Enumerated 660 servers in: 5.86 Seconds.
```

## Output: 
### openvpn:
`head -n 20 openvpn_09.02.2025.csv | column -t -s ,`

![ovpnEg](https://github.com/user-attachments/assets/6c2460e7-2adc-4a92-91f7-e551b5c4c1ee)

### wireguard:

`head -n 20 wireguard_09.02.2025.csv | column -t -s ,`

![wireguardEg](https://github.com/user-attachments/assets/996f03e1-73fe-4be0-adbc-455f1443fafc)

