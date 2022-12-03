#Extract SSL certificates from list of websites and sending email of pending expiration if within next 30 days

import ssl, socket
from datetime import datetime,date
import OpenSSL
from dateutil import parser
import boto3
import os

expiration= []
body_text_string=[]

ipfile=open('server_ip.txt')  #Text file to list websites you want to check
print("Program to check SSL certification validity and expiration date\n")

access_key = os.getenv('accesskeyid')  #Need access key and id as iam using production account
access_secret = os.environ.get('accesskeysecret')

ses_client = boto3.client("ses", region_name="us-east-1",aws_access_key_id=access_key, aws_secret_access_key=access_secret)  #client contact with ses

# loop iterates through all the servers and gets their expiration date, stores expiration and server name in a list
for ip in ipfile:
    address = ip.split(":")
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=address[0]) as s:
        s.connect((address[0], 443))
        cert = s.getpeercert()
        #print(cert['notAfter'])
        res = parser.parse(cert['notAfter'], fuzzy=True)
        #print(res.date())
        current_day = date.today()
        #print(current_day)
        days_left=(res.date()-current_day).days
        print(f"Checking certifcate for server {address[0]}")  # prints name of server
        print(f"Expires on {res.date()} in {days_left} in days")  # prints date of expiration
        expiration.append({"server":address[0],"expirationdate":days_left})
    #expiration["expirationdate"].append(days_left)

# loop iterates through all the servers and checks if their exporation is in next 30 days. If true sends an email with the list of servers that are expiring in less than 30 days
for expiry in expiration:

    if expiry['expirationdate']<30:

        body_text_string.append(f"Certificate for {expiry['server']} expires in {expiry['expirationdate']} days")

if body_text_string:
    body_text='\n'.join(body_text_string)
    CHARSET = "UTF-8"
    response = ses_client.send_email(
    Destination={
        "ToAddresses": [
            "vramshesh@gmail.com",    #Registered email in SES
        ],
    },
    Message={
        "Body": {
            "Text": {
                "Charset": CHARSET,
                "Data": body_text
                    }
                },
        "Subject": {
            "Charset": CHARSET,
            "Data": "SSL certificate expiration",
                    },
            },
                Source="vramshesh@gmail.com",
            )