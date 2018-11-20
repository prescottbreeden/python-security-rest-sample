"""Configuration settings for running the Python auth samples locally.

In a production deployment, this information should be saved in a database or
other secure storage mechanism.
"""

# Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
# See LICENSE in the project root for license information.

CLIENT_ID = 'ENTER_YOUR_APP_ID_HERE'
CLIENT_SECRET = 'ENTER_YOUR_APP_SECRET_HERE'
REDIRECT_URI = 'http://localhost:5000/login/authorized'

WEBHOOK_DATA = {'changeType': 'updated',
    'notificationUrl': 'https://{ NGROK_URL_HERE }/listen',
    'resource': 'security/alerts',
    'clientState': 'cLIENTsTATEfORvALIDATION'
}

# AUTHORITY_URL ending determines type of account that can be authenticated:
# /organizations = organizational accounts only
# /consumers = MSAs only (Microsoft Accounts - Live.com, Hotmail.com, etc.)
# /common = allow both types of accounts
AUTHORITY_URL = 'https://login.microsoftonline.com/common'

AUTH_ENDPOINT = '/oauth2/v2.0/authorize'
TOKEN_ENDPOINT = '/oauth2/v2.0/token'

RESOURCE = 'https://graph.microsoft.com/'
API_VERSION = 'v1.0'
ISG_VERSION = 'v1.0'
ISG_URL = RESOURCE + ISG_VERSION +'/security/'
SCOPES = ['User.Read'] # Add other scopes/permissions as needed.

# This code can be removed after configuring CLIENT_ID and CLIENT_SECRET above.
if 'ENTER_YOUR' in CLIENT_ID or 'ENTER_YOUR' in CLIENT_SECRET:
    print('ERROR: config.py does not contain valid CLIENT_ID and CLIENT_SECRET')
    import sys
    sys.exit(1)
