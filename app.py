import os
import re
import time
import datetime
import smtplib
import win32evtlog
import win32net
import win32security
import winreg
import subprocess
import ipaddress
from colorama import Fore, Back, Style
import configparser
import json

config = configparser.ConfigParser()
config.read('config.ini')

# APP Settings [DONT CHANGE ANY THING IN THIS FILE IF YOU WANT CHANGE SETTINGS PLEASE EDIT config.ini FILE]

# Specify the event log to monitor and the types of events to look for
event_log = config.get('EVENTS', 'event_log')

event_type = config.get('EVENTS', 'event_type')
event_ids = config.get('EVENTS', 'event_ids').split(',')

# Specify the number of failed attempts to trigger a ban, and the duration of the ban in seconds
max_failures = config.getint('BAN', 'max_failures')
ban_duration = config.getint('BAN', 'ban_duration') * 60

# Specify the email settings for sending notifications
send_notification = config.getboolean('EMAIL', 'send_notification')
smtp_server = config.get('EMAIL', 'smtp_server')
smtp_port = config.getint('EMAIL', 'smtp_port')
smtp_username = config.get('EMAIL', 'smtp_username')
smtp_password = config.get('EMAIL', 'smtp_password')
from_email = config.get('EMAIL', 'from_email')
to_email = config.get('EMAIL', 'to_email')

# List of trusted IPs and IP ranges
whitelist = config.get('IP', 'whitelist').split(',')

# Connect to the Windows event log service
hand = win32evtlog.OpenEventLog(None, event_log)
flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
events = win32evtlog.ReadEventLog(
    hand, flags, 0, win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ)
bookmark = win32evtlog.GetOldestEventLogRecord(hand) - 1
events = win32evtlog.ReadEventLog(hand, flags, bookmark)
bookmark = events[-1].RecordNumber
# bookmark = win32evtlog.GetNewestEventLogRecord(hand)

# Create regular expression patterns to extract the IP address and username from the log message
ip_pattern = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?')
username_pattern = re.compile(r'(?P<username>[\w\-\.]+\\[\w\-\.]+)')

# Initialize the blacklist and failure counters
try:
    with open('blacklist.json', 'r') as f:
        blacklist = json.load(f)
except FileNotFoundError:
    blacklist = {}


# Function to save the blacklist to file

def save_blacklist():
    with open('blacklist.json', 'w') as f:
        json.dump(blacklist, f)

# Function to save the banned ip history to file


def save_banned_ip(ip):
    # Create or update the banned IP log file
    file_path = 'banned_IP_log.ini'
    if os.path.exists(file_path):
        config = configparser.ConfigParser()
        config.read(file_path)
        if ip in config:
            # Increment the previous ban count
            prev_ban_count = int(config[ip]['prev_ban_count']) + 1
            config.set(ip, 'prev_ban_count', str(prev_ban_count))
        else:
            # Add a new banned IP entry
            config[ip] = {'date': datetime.datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S'), 'prev_ban_count': '1'}
    else:
        # Create a new banned IP log file
        config = configparser.ConfigParser()
        config[ip] = {'date': datetime.datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S'), 'prev_ban_count': '1'}
    with open(file_path, 'w') as f:
        config.write(f)


failures = {}

# Function to check if given IP is white listed or not


def check_whitelist(ip):
    # Converting IP string to ipaddress object
    ip_obj = ipaddress.ip_address(ip)

    # Iterating over the white list items
    for item in whitelist:
        # Converting whitelist item to ipaddress object
        whitelist_obj = ipaddress.ip_network(item)

        # Checking if given IP is in whitelisted range or not
        if ip_obj in whitelist_obj:

            # If yes, return True
            return True
    # If not, return False
    return False


while True:

    # Read the next event from the event log
    events = win32evtlog.ReadEventLog(hand, flags, bookmark)
    # print(type(events), events)
    if not events:
        print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Ready ! ',
              end='\r', flush=True)
        time.sleep(1)
        continue

    for event in events:
        # Update the bookmark to the next event to be processed
        bookmark = event.RecordNumber
        # if event_type in event.SourceName and str(event.EventID) in event_ids:
        if str(event.EventID) in event_ids:
            # Extract the IP address and username from the log message
            message = ' '.join([str(s) for s in event.StringInserts])
            ip_match = ip_pattern.search(message)

            if not ip_match:
                continue

            ip = ip_match.group('ip')

            # Check if ip white listed
            if check_whitelist(ip):
                failures[ip] = failures.get(ip, 0) + 1
                print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: ' + Fore.GREEN +
                      f' activity detected from ip : {ip} [wihitelisted] attemps {failures[ip]}/unlimited Event id : {event.EventID}' + Style.RESET_ALL)
                continue

            if ip in blacklist:
                print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}:' +
                      Fore.RED + f' Blocked traffic from {ip}' + Style.RESET_ALL)
                continue

            # Update the failure counter for this IP address

            failures[ip] = failures.get(ip, 0) + 1
            print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: ' + Fore.YELLOW +
                  f'Suspicious activity detected from ip : {ip} attemps {failures[ip]}/{max_failures} Event id : {event.EventID}' + Style.RESET_ALL)

            # Check if the failure count for this IP address has reached the maximum
            if failures[ip] >= max_failures:
                # Add the IP address to the blacklist and create a firewall rule to block traffic from it

                # Check ip ban history
                file_path = 'banned_IP_log.ini'
                prev_ban_count = 1
                if os.path.exists(file_path):
                    config = configparser.ConfigParser()
                    config.read(file_path)
                    if ip in config:
                        prev_ban_count = int(config[ip]['prev_ban_count'], 0)

                blacklist[ip] = time.time() + ban_duration * \
                    (prev_ban_count * prev_ban_count)
                save_blacklist()
                save_banned_ip(ip)
                print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}:' + Fore.GREEN +
                      f' Added {ip} to blacklist for {ban_duration * (prev_ban_count * prev_ban_count) /60} Minutes, ban count: {prev_ban_count}' + Style.RESET_ALL)
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name=SecureShield BlockIP {ip}',
                               f'protocol=any', f'dir=in', f'action=block', f'remoteip={ip}'])

                # Send an email notification
                if send_notification:
                    try:
                        # Send an email notification
                        subject = "SecureShiled Blacklist Notification"
                        body = f'The IP address {ip} has been added to the blacklist for {ban_duration * (prev_ban_count * prev_ban_count )/60 } Minutes,  Event id : {event.EventID}'
                        message = f"Subject: {subject}\n\n{body}"
                        server = smtplib.SMTP(smtp_server, smtp_port)
                        server.starttls()
                        server.login(smtp_username, smtp_password)
                        server.sendmail(from_email, to_email, message)
                        server.quit()

                        print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}:' + Fore.GREEN +
                              f' Email notification sent successfully to: {to_email}' + Style.RESET_ALL)

                    except Exception as e:
                        print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}:' +
                              Fore.RED + f' Error sending email notification: {e}' + Style.RESET_ALL)

            # Check if any IP addresses in the blacklist have expired, and remove them if necessary
            now = time.time()
            for ip, expiration in list(blacklist.items()):
                if now > expiration:
                    del blacklist[ip]
                    save_blacklist()
                    print(f'{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: ' +
                          Fore.GREEN + f'Removed {ip} from blacklist' + Style.RESET_ALL)
                    subprocess.run(['netsh', 'advfirewall', 'firewall',
                                    'delete', 'rule', f'name=SecureShield BlockIP {ip}', f'remoteip={ip}'])
            print(f'we have {len(blacklist)} ip\'s in black list.')

            # Sleep for a short interval before checking the event log again
            # time.sleep(1)
