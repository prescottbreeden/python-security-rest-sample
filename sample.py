"""sample for Microsoft Graph ISG"""
# Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
# See LICENSE in the project root for license information.
import gevent
from gevent import monkey
monkey.patch_all()

import base64
import mimetypes
import pprint
import uuid
import datetime
import time
import urllib
import json
from functools import wraps

import flask
from flask_oauthlib.client import OAuth
from flask_socketio import SocketIO, emit, join_room
from flask_session import Session
import gevent
from gevent import monkey
monkey.patch_all()

import config

APP = flask.Flask(__name__, template_folder='static/templates')
APP.debug = True
APP.secret_key = 'development'
APP.config['SESSION_TYPE'] = 'filesystem'

Session(APP)
socketio = SocketIO(APP, manage_session=False, async_mode="gevent")
OAUTH = OAuth(APP)
MSGRAPH = OAUTH.remote_app(
    'microsoft',
    consumer_key=config.CLIENT_ID,
    consumer_secret=config.CLIENT_SECRET,
    request_token_params={'scope': config.SCOPES},
    base_url=config.RESOURCE + config.API_VERSION + '/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url=config.AUTHORITY_URL + config.TOKEN_ENDPOINT,
    authorize_url=config.AUTHORITY_URL + config.AUTH_ENDPOINT)


@APP.route('/')
def homepage():
    """Render the home page."""
    if 'VIEW_DATA' not in flask.session:
        flask.session['VIEW_DATA'] = {} #used to store items that should be rendered in the HTML
    if 'access_token' in flask.session:
        if 'email' not in flask.session or 'username' not in flask.session :
            return flask.redirect(flask.url_for('get_my_email_address'))
        if 'SecurityEvents.ReadWrite.All' not in flask.session['scopes']:
            return flask.render_template('Admin_consent.html', Title="Microsoft Security Graph API demo web application"
                                 ,Year=datetime.date.today().strftime("%Y")
                                 ,ViewData=flask.session['VIEW_DATA'], Config=config)
    # print("ViewData", flask.session['VIEW_DATA'])
    return flask.render_template('Graph.html', Title="Microsoft Security Graph API demo web application"
                                 ,Year=datetime.date.today().strftime("%Y")
                                 ,ViewData=flask.session['VIEW_DATA'], Config=config)

@APP.route('/login')
def login():
    """Prompt user to authenticate."""
    # flask.session['VIEW_DATA'].clear()
    flask.session.clear()
    flask.session['state'] = str(uuid.uuid4())
    return MSGRAPH.authorize(callback=config.REDIRECT_URI, state=flask.session['state'])

@APP.route('/login/authorized')
def authorized():
    """Handler for the application's Redirect Uri."""
    # redirected admin consent flow
    if flask.request.args.get('error') :
        if flask.request.args.get('error_subcode'):
            error_description = flask.request.args.get('error_subcode')
        else :
            error_description = flask.request.args['error_description']
        message = '<strong>Error:</strong> ' + flask.request.args['error'] + '</br> <strong>Reason:</strong> ' + error_description
        flask.flash(message, category='danger')
        return flask.redirect('/')
    elif flask.request.args.get('admin_consent') :
        message = '<strong>Success</strong> Tenant: ' + flask.request.args['tenant'] + ' has given this application admin consent.'
        flask.flash(message, category='success')
        flask.session.pop('access_token', None) 
        flask.session['VIEW_DATA'].clear()
        return flask.redirect('/')
    # redirected from authentication
    print("flask.request.args : ", flask.request.args)
    print("flask.session.state : ", flask.session.get('state'))
    if flask.session.get('state') and str(flask.session['state']) != str(flask.request.args.get('state')):
        raise Exception('state returned to redirect URL does not match!')
    response = MSGRAPH.authorized_response()
    # print("authorized response : ", response)
    expires_in =  datetime.datetime.now() + datetime.timedelta(seconds=response.get('expires_in', 3599))
    print("access token expires at ", expires_in)
    flask.session["token_expires_in"] = expires_in
    flask.session['access_token'] = response['access_token']
    flask.session['scopes'] = response['scope'].split()
    flask.session['providers'] = get_providers()
    return flask.redirect('/')

def get_providers():
    top_alerts = get_top_security_alert()
    providers = []
    # print(top_alerts)
    if (top_alerts) :
        for alert in top_alerts.get('value'):
            providers.append(alert.get("vendorInformation").get("provider"))
    return providers


@APP.route('/logout')
def logout():
    """signs out the current user from the session."""
    #flask.session.pop('access_token', None) 
    flask.session.clear()
    # flask.session['VIEW_DATA'].clear()
    return flask.redirect(flask.url_for('homepage'))

#Used to decorate methods that require authentication.
def requires_auth(f):
  """Wrapper function to prompt user to authenticate."""
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'access_token' not in flask.session:
      # Redirect to Login page
      return flask.redirect('/login')
    if flask.session["token_expires_in"] < datetime.datetime.now():
        #If the access token is expired, require the user to login again
        return flask.redirect('/login')
    return f(*args, **kwargs)
  return decorated

@APP.route('/GetMyEmailAddress')
@requires_auth
def get_my_email_address():
    """Make Rest API call to graph for current users email"""
    flask.session['VIEW_DATA'].clear() # reset data passed to the Graph.html
    user_profile = MSGRAPH.get('me', headers=request_headers()).data
    if 'error' in user_profile: ### Access token has expired!
        #print(user_profile)
        if user_profile['error']['code'] == 'InvalidAuthenticationToken':
            return flask.redirect(flask.url_for('login'))
       
    flask.session['email'] = user_profile['userPrincipalName']
    flask.session['username'] = user_profile['displayName']
    return flask.redirect(flask.url_for('homepage'))

@APP.route('/GetAlerts', methods = ['POST', 'GET'])
@requires_auth
def get_alerts():
    """Make Rest API call to security graph for alerts"""
    if flask.request.method == 'POST':
        result = flask.request.form
        alert_data = {}
        flask.session['VIEW_DATA'].clear()
        for key in result:
            alert_data[key] = result[key]
        flask.session['alertData'] = alert_data
         
        filteredAlerts = get_alerts_from_graph()
        if b'' in filteredAlerts:
            print("Please Sign-in using a on.microsoft.com account for demo data")
            filteredAlerts = "Incorrect Tenant Account"
        elif 'error' in filteredAlerts:
            if filteredAlerts['error']['code'] == 'InvalidAuthenticationToken':

                return flask.redirect(flask.url_for('login'))

        flask.session['VIEW_DATA']['GetAlertResults'] = filteredAlerts

        MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return flask.redirect(flask.url_for('homepage'))

def get_alerts_from_graph():
    """Helper to Make Rest API call to graph by building the query"""
    MSGRAPH.base_url = config.ISG_URL
    alert_data = flask.session['alertData']
    filteredQuery = ""
    if 'AssignedToMe' in alert_data :
        filteredQuery += "assignedTo eq '" + flask.session['email'] +"'"
    if not alert_data:
        flask.session['VIEW_DATA']['QueryDetails'] = "REST query: '" + MSGRAPH.base_url + 'alerts/?$top=5' + "'"
        return MSGRAPH.get('alerts/?$top=5', headers=request_headers()).data
    else:
        filteredQuery += build_filter_query(alert_data)
        filteredQuery += '$top=' if (len(filteredQuery) == 0) else '&$top='
        filteredQuery += alert_data['Top']

    addFilter = ""
    if filteredQuery != ("$top=" + alert_data['Top']):
        addFilter = '$filter='

    query = "alerts/?" + addFilter + filteredQuery
    flask.session['VIEW_DATA']['QueryDetails'] = query
    query = urllib.parse.quote(query,safe="/?$='&") #cleans up the url
    return MSGRAPH.get(query, headers=request_headers()).data

def build_filter_query(form):
    filteredQuery = ""
    if ('Category'in form and form['Category'] != "All"):
        filteredQuery += 'category eq ' if (len(filteredQuery) == 0) else ' and category eq '
        filteredQuery += "'{}'".format(form['Category'])
    if ('Provider' in form and form['Provider'] != "All"):
        filteredQuery += 'vendorInformation/provider eq ' if (len(filteredQuery) == 0) else ' and vendorInformation/provider eq '
        filteredQuery += "'{}'".format(form['Provider'])
    if ('Status' in form and form['Status'] != "All"):
        filteredQuery += 'Status eq ' if (len(filteredQuery) == 0) else ' and Status eq '
        filteredQuery += "'{}'".format(form['Status'])
    if ('Severity' in form and form['Severity'] != "All"):
        filteredQuery += 'Severity eq ' if (len(filteredQuery) == 0) else ' and Severity eq '
        filteredQuery += "'{}'".format(form['Severity'])
    if ('HostFqdn' in form and form['HostFqdn'] != ""):
        filteredQuery += "hostStates/any(a:a/fqdn eq " if (len(filteredQuery) == 0) else ' and hostStates/any(a:a/fqdn eq '
        filteredQuery += "'{}')".format(form['HostFqdn'])
    if ('Upn' in form and form['Upn'] != ""):
        filteredQuery += 'userStates/any(a:a/userPrincipalName eq ' if (len(filteredQuery) == 0) else ' and userStates/any(a:a/userPrincipalName eq '
        filteredQuery += "'{}')".format(form['Upn'])
    return filteredQuery


@APP.route('/DisplayAlert/<alertId>')
@requires_auth
def display_alert(alertId):
    """Renders the alert page"""
    alert = get_alert_by_id(alertId)
    jsonAlert = json.dumps(alert, sort_keys=True, indent=4, separators=(',', ': '))
    return flask.render_template('alert.html', Title="Alert Details"
                                ,Year=datetime.date.today().strftime("%Y")
                                ,Alert=jsonAlert, AlertId=alertId, Config=config)

def get_alert_by_id(alertId):
    """Helper function to get a security alert by ID
    
    alertId      = The Alert ID to be updated

    Returns the response from Graph
    """
    MSGRAPH.base_url = config.ISG_URL
    alert = MSGRAPH.get('alerts/' + alertId, headers=request_headers()).data
    if b'' in alert:
       print("Please Sign-in using a on.microsoft.com account for demo data")
       alert = None
    elif 'error' in alert:
        alert = None
    elif '@odata.context' in alert: # remove ODATA entity
        del alert['@odata.context']
    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return alert

def update_security_alert(alertId, newData):
    """Helper to Update a security graph alert.

    alertId      = The Alert ID to be updated
    newData      = The json body of the PATCH rest call
    """
    MSGRAPH.base_url = config.ISG_URL
    _ = MSGRAPH.patch('alerts/' + alertId, data=newData, headers=request_headers(),  format='json')
    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return

def get_top_security_alert():
    """Helper to get the most recent security graph alert."""
    MSGRAPH.base_url = config.ISG_URL
    most_recent_alert = MSGRAPH.get('alerts/?$top=1', headers=request_headers()).data
    if b'' in most_recent_alert:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        most_recent_alert = None
    elif 'error' in most_recent_alert:
        most_recent_alert = None
    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return most_recent_alert

def create_webhook_subscription(webhook_body):
    """Helper to create a webhook subscription."""
    MSGRAPH.base_url = config.RESOURCE
    subscription = MSGRAPH.post(config.ISG_VERSION + '/subscriptions', data=webhook_body, headers=request_headers(), format='json').data
    print("Create subscription response", subscription)
    if b'' in subscription:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        subscription = None
    elif 'error' in subscription:
        if subscription['error']['code'] == 'InvalidAuthenticationToken':
            return flask.redirect(flask.url_for('login'))
        if subscription['error']['message'] == 'Subscription validation request failed. Must respond with 200 OK to this request.':
            message = "<strong>Error:</strong> Please run 'ngrok' to allow the webhook notification sevice to access your app, then update the config.py file to the correct ngrok url."
            flask.flash(message, category='danger')
    else:
        message = '<strong>Success</strong> Webhook subscription created. Id: ' + subscription.get('id')
        flask.flash(message, category='success')

    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return subscription

def update_webhook_subscription(subscription_id, webhook_body):
    """Helper to update a webhook subscription."""
    MSGRAPH.base_url = config.RESOURCE 
    subscription = MSGRAPH.patch(config.ISG_VERSION + '/subscriptions/' + subscription_id , data=webhook_body, headers=request_headers(), format='json').data
    print("Update subscription response", subscription)
    if b'' in subscription:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        subscription = None
    elif 'error' in subscription:
        if subscription['error']['code'] == 'InvalidAuthenticationToken':
            return flask.redirect(flask.url_for('login'))
    else:
        message = '<strong>Success</strong> Webhook subscription updated. Id: ' + subscription.get('id')
        flask.flash(message, category='success')

    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return subscription

def get_webhook_subscriptions():
    """Helper to get all current webhook subscriptions for the application."""
    MSGRAPH.base_url = config.RESOURCE    
    # print("MSGRAPH.base_url", MSGRAPH.base_url) 
    subscriptions = MSGRAPH.get(config.ISG_VERSION + '/subscriptions').data
    print("Active subscriptions :", subscriptions)
    if b'' in subscriptions:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        subscriptions = None
    elif 'error' in subscriptions:
        if subscriptions['error']['code'] == 'InvalidAuthenticationToken':

            return flask.redirect(flask.url_for('login'))

    MSGRAPH.base_url = config.RESOURCE + config.API_VERSION + '/'
    return subscriptions

@APP.route('/UpdateAlert', methods = ['POST', 'GET'])
@requires_auth
def update_alert():
    """ Make Rest API call to security graph to update an alert """
    if flask.request.method == 'POST':
        flask.session.pop('UpdateAlertData', None)
        result = flask.request.form
        flask.session['VIEW_DATA'].clear()
        alert_data = {_:result[_] for _ in result} #Iterate over html form POST from Graph.html
        if alert_data.get('AlertId'): # Id form was not empty
            alert_data['AlertId'] = alert_data.get('AlertId').strip(' ')
        else:
            flask.session['VIEW_DATA']['UpdateAlertError'] = "Please enter valid alert Id"
            return flask.redirect(flask.url_for('homepage'))
        alertId = alert_data['AlertId']
        old_alert = get_alert_by_id(alertId) # store old alert before updating it
        if not old_alert: # alert not found
            flask.session['VIEW_DATA']['UpdateAlertError'] = "No alert matching this ID " + alertId + " was found"
            return flask.redirect(flask.url_for('homepage'))
        else: 
            flask.session['VIEW_DATA']['OldAlert'] = old_alert
            properties_to_update = {}
            properties_to_update["assignedTo"] = flask.session['email']
            if alert_data.get("SelectStatusToUpdate") != "Unknown":
                properties_to_update["status"] = alert_data.get("SelectStatusToUpdate")
            if alert_data.get("SelectFeedbackToUpdate") != "Unknown":
                properties_to_update["feedback"] = alert_data.get("SelectFeedbackToUpdate")
            if alert_data.get("Comments") != "":
                comments = old_alert.get("comments")
                new_comment= alert_data.get("Comments")
                comments.append(new_comment)
                properties_to_update["comments"] = comments
            # include the required vendor information in the body of the PATCH
            properties_to_update["vendorInformation"] = old_alert.get("vendorInformation")
            # update the alert
            update_security_alert(alertId, properties_to_update)
            # make another call to graph to get the updated alert
            updated_alert = get_alert_by_id(alertId)
            #store the alert to be rendered in the table in Graph.html
            flask.session['VIEW_DATA']['UpdateAlertResults'] = updated_alert
            flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query PATCH: '" + config.ISG_URL +"alerts/" + alertId + "'"
            flask.session['VIEW_DATA']['UpdateQueryBody'] = "Request Body: " + json.dumps(properties_to_update, sort_keys=True, indent=4, separators=(',', ': '))
        flask.session['UpdateAlertData'] = alert_data
    return flask.redirect(flask.url_for('homepage'))

@APP.route('/Subscribe', methods = ['POST', 'GET'])
@requires_auth
def subscribe():
    if flask.request.method == 'POST':
        flask.session['VIEW_DATA'].clear()
        webhook_form = {}
        for key in flask.request.form:
            webhook_form[key] = flask.request.form[key]
        flask.session['VIEW_DATA']['WebhookForm'] = webhook_form
        filter_query = build_filter_query(webhook_form)
        print("filter_query: ", filter_query)
        if filter_query == '':
            message = '<strong>Error:</strong> Subscription requires at least one filter parameter.'
            flask.flash(message, category='danger')
            return flask.redirect(flask.url_for('homepage'))
        else:
            webhook_body = config.WEBHOOK_DATA
            webhook_body['resource'] = 'security/alerts?$filter=' + filter_query

            active_subscriptions = get_webhook_subscriptions() # Check subscriptions to prevent repeat
            expirationDateTime = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            old_sub = None
            if len(active_subscriptions) > 0:
                for sub in active_subscriptions.get('value'):
                    if sub.get('resource') == webhook_body['resource']:
                        print("repeated resource")
                        old_sub = sub
                        break
            if old_sub: # PATCH the current webhook subscription instead of creating a duplicate subscription
                webhook_body = {}
                webhook_body['expirationDateTime'] = expirationDateTime.isoformat() + "Z"
                response = update_webhook_subscription(old_sub.get("id"), webhook_body)
                if response :
                    print("PATCH response: ", response)
                    flask.session['VIEW_DATA']["webhook_sub"] = [response]
                    flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query PATCH: '" + config.RESOURCE + config.ISG_VERSION + "/subscriptions/" + old_sub.get("id") + "'"
                    flask.session['VIEW_DATA']['UpdateQueryBody'] = "Request Body: " + json.dumps(webhook_body, sort_keys=True, indent=4, separators=(',', ': '))
            else:
                webhook_body['expirationDateTime'] = expirationDateTime.isoformat() + "Z"
                print('expirationDateTime', webhook_body['expirationDateTime'])
                print('webhook_body', webhook_body)
                response = create_webhook_subscription(webhook_body)
                if response :
                    print("POST response: ", response)
                    flask.session['VIEW_DATA']["webhook_sub"] = [response]
                    flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query POST: '" + config.RESOURCE + config.ISG_VERSION + "/subscriptions'"
                    flask.session['VIEW_DATA']['UpdateQueryBody'] = "Request Body: " + json.dumps(webhook_body, sort_keys=True, indent=4, separators=(',', ': '))

    if flask.request.method == 'GET':
        flask.session['VIEW_DATA'].clear()
        active_subscriptions = get_webhook_subscriptions()
        if active_subscriptions :
                flask.session['VIEW_DATA']["webhook_sub"] = active_subscriptions.get('value')
                flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query GET: '" + config.RESOURCE + config.ISG_VERSION + "/subscriptions'"

    return flask.redirect(flask.url_for('homepage'))

@APP.route('/listen', methods = ['POST', 'GET'])
def listen():
    if flask.request.method == 'POST':
        validationToken = flask.request.args.get('validationToken', '')
        if validationToken != '':
            return flask.make_response(validationToken, 200)
        else:
            notification = flask.request.get_json()
            print('notification_received :', notification)
            if notification['value'] and len(notification['value']) > 0:
                sess = notification['value'][0].get('clientState')
                if sess:
                    socketio.emit("notification_received", notification, namespace='/listen') 

            return flask.make_response('',202)

    if flask.request.method == 'GET': 
        return flask.render_template('notification.html', Title="Microsoft Security Graph API demo web application"
                                 ,Year=datetime.date.today().strftime("%Y"))


@socketio.on('connect', namespace='/listen')
def test_connect():
    print("connected")


@MSGRAPH.tokengetter
def get_token():
    """Called by flask_oauthlib.client to retrieve current access token."""
    return (flask.session.get('access_token'), '')


def request_headers(headers=None):
    """Return dictionary of default HTTP headers for Graph API calls.
    Optional argument is other headers to merge/override defaults."""
    default_headers = {'SdkVersion': 'sample-python-flask',
                       'x-client-SKU': 'sample-python-flask',
                       'client-request-id': str(uuid.uuid4()),
                       'return-client-request-id': 'true'}
    if headers:
        default_headers.update(headers)
    return default_headers


if __name__ == '__main__':

    socketio.run(APP)

