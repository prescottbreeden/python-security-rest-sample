############### notificationURL?
"""Configuration settings for running the Python auth samples locally.

In a production deployment, this information should be saved in a database or
other secure storage mechanism.
"""

# Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
# See LICENSE in the project root for license information.

# Application Id?
CLIENT_ID = 'bc3fb16e-01eb-46b0-a26b-f0f80daa245b'
CLIENT_SECRET = 'M3]JUf@19JA=DUzsTaO*dd0e-f]vIdEf'
REDIRECT_URI = 'http://localhost:5000/login/authorized'

WEBHOOK_DATA = {'changeType': 'updated',
                'notificationUrl': 'https://http://62673013.ngrok.io/listen',
                'resource': 'security/alerts',
                'clientState': 'cLIENTsTATEfORvALIDATION'}

# AUTHORITY_URL ending determines type of account that can be authenticated:
# /organizations = organizational accounts only
# /consumers = MSAs only (Microsoft Accounts - Live.com, Hotmail.com, etc.)
# /common = allow both types of accounts
AUTHORITY_URL = 'https://login.microsoftonline.com/organizations'

AUTH_ENDPOINT = '/oauth2/v2.0/authorize'
TOKEN_ENDPOINT = '/oauth2/v2.0/token'

RESOURCE = 'https://graph.microsoft.com/'
API_VERSION = 'v1.0'
SECURITYAPI_VERSION = 'v1.0'
SECURESCORE_VERSION = 'v1.0'
SECURITYACTION_VERSION = 'beta'
SECURITYAPI_URL = RESOURCE + SECURITYAPI_VERSION + '/security/'
SCOPES = ['User.Read', 'SecurityEvents.ReadWrite.All']  # Add other scopes/permissions as needed.

# This code can be removed after configuring CLIENT_ID and CLIENT_SECRET above.
if 'ENTER_YOUR' in CLIENT_ID or 'ENTER_YOUR' in CLIENT_SECRET:
    print('ERROR: config.py does not contain valid CLIENT_ID or CLIENT_SECRET')
    import sys
    sys.exit(1)
