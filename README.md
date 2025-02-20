# SecureShield - IP Blocker and Event Log Monitor

**SecureShield** is an automated IP blocking and event log monitoring system designed to protect against suspicious activity on a Windows machine. The application reads Windows event logs for specific event IDs, tracks failed login attempts, and blocks IP addresses after a defined number of failures. It also notifies the admin by email when an IP is blacklisted.

## Features

- **Windows Event Log Monitoring**: Continuously reads the Windows event logs to detect suspicious activity, such as failed login attempts.
- **IP Blacklisting**: Automatically blacklists IPs that exceed a predefined number of failed attempts.
- **Firewall Integration**: Uses Windows firewall to block blacklisted IPs.
- **Whitelist Support**: Allows trusted IPs to bypass the detection and blocking mechanism.
- **Email Notification**: Sends email notifications when an IP is blacklisted.
- **Ban Duration**: Allows you to set a duration for how long an IP remains banned.
- **Blacklist Persistence**: Stores the blacklisted IPs and their associated ban times in a JSON file.
- **Event History Tracking**: Tracks and logs the history of banned IPs with timestamps and ban counts.

## Requirements

- **Python** 3.6+
- **Required Python libraries**:
  - `colorama`
  - `pywin32`
  - `configparser`
  - `json`
  - `ipaddress`
  - `smtplib`
  
To install the necessary libraries, run:

```bash
pip install colorama pywin32 configparser
```
## Developer
This application was developed by Mahmoud Abdelhamid.

## License
This project is licensed under the MIT License.

## Copyright
© 2025 Mahmoud Abdelhamid. All rights reserved.
