"""Sample for Microsoft Graph Security API"""
# Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
# See LICENSE in the project root for license information.

import gevent.monkey
gevent.monkey.patch_all()

import uuid
import datetime
import urllib
import json
from functools import wraps

import flask
from requests_oauthlib import OAuth2Session
from flask_socketio import SocketIO
from flask_session import Session

import config


APP = flask.Flask(__name__, template_folder='static/templates')
APP.debug = True
APP.secret_key = 'development'
APP.config['SESSION_TYPE'] = 'filesystem'

if APP.secret_key == 'development':
    # ONLY TO BE USED IN DEVELOPMENT 
    import os
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # allows http requests
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'  # allows tokens to contain additional permissions
    

Session(APP)
SOCKETIO = SocketIO(APP, manage_session=False, async_mode="gevent")
MSGRAPH = OAuth2Session(config.CLIENT_ID,
                        redirect_uri=config.REDIRECT_URI,
                        scope=config.SCOPES)


@APP.route('/')
def homepage():
    """Render the home page."""
    if 'VIEW_DATA' not in flask.session:
        flask.session['VIEW_DATA'] = {}  # used to store items that should be rendered in the HTML
    if 'access_token' in flask.session:
        if 'email' not in flask.session or 'username' not in flask.session:
            return flask.redirect(flask.url_for('get_my_email_address'))
        if 'SecurityEvents.ReadWrite.All' not in flask.session['scopes']:
            return flask.render_template('Admin_consent.html',
                                         Title="Microsoft Graph Security API demo web application",
                                         Year=datetime.date.today().strftime("%Y"),
                                         ViewData=flask.session['VIEW_DATA'],
                                         Config=config)
    # print("ViewData", flask.session['VIEW_DATA'])

    return flask.render_template('Graph.html',
                                 Title="Microsoft Graph Security API demo web application",
                                 Year=datetime.date.today().strftime("%Y"),
                                 ViewData=flask.session['VIEW_DATA'],
                                 Config=config)


@APP.route('/login')
def login():
    """Prompt user to authenticate."""
    flask.session.clear()
    authorization_url, state = MSGRAPH.authorization_url(config.AUTHORITY_URL + config.AUTH_ENDPOINT)
    flask.session['state'] = state
    return flask.redirect(authorization_url)


@APP.route('/login/authorized')
def authorized():
    """Handler for the application's Redirect Uri."""
    # redirected admin consent flow
    if flask.request.args.get('error'):
        if flask.request.args.get('error_subcode'):
            error_description = flask.request.args.get('error_subcode')
        else:
            error_description = flask.request.args['error_description']
        message = '<strong>Error:</strong> ' \
                  + flask.request.args['error'] \
                  + '</br> <strong>Reason:</strong> ' \
                  + error_description
        flask.flash(message, category='danger')
        return flask.redirect('/')
    elif flask.request.args.get('admin_consent'):
        message = '<strong>Success</strong> Tenant: ' \
                  + flask.request.args['tenant'] \
                  + ' has given this application admin consent.'
        flask.flash(message, category='success')
        flask.session.pop('access_token', None) 
        flask.session['VIEW_DATA'] = {}
        return flask.redirect('/')
    # redirected from authentication
    # print("flask.request.args : ", flask.request.args)
    # print("flask.session.state : ", flask.session.get('state'))

    if flask.session.get('state') and str(flask.session['state']) != str(flask.request.args.get('state')):
        raise Exception('state returned to redirect URL does not match!')
    token = MSGRAPH.fetch_token(config.AUTHORITY_URL + config.TOKEN_ENDPOINT,
                                client_secret=config.CLIENT_SECRET,
                                authorization_response=flask.request.url)

    expires_in = datetime.datetime.now() + datetime.timedelta(seconds=token.get('expires_in', 3599))
    print("access token expires at ", expires_in)
    flask.session["token_expires_in"] = expires_in
    flask.session['access_token'] = token
    flask.session['scopes'] = token['scope']
    flask.session['providers'] = get_providers()
    flask.session['secure_scores'] = get_secure_score()
    flask.session['secure_score_profiles'] = get_secure_score_control_profiles()
    return flask.redirect('/')


def get_providers():
    """ returns an array of providers """
    top_alerts = get_top_security_alert()
    providers = []
    provider_map = {}
    # print(top_alerts)
    if top_alerts:
        for alert in top_alerts.get('value'):
            _vendor_info = alert.get("vendorInformation")
            _provider_name = _vendor_info.get("provider")
            providers.append(_provider_name)
            provider_map[_provider_name] = _vendor_info
    flask.session['provider_map'] = provider_map
    return providers


@APP.route('/logout')
def logout():
    """signs out the current user from the session."""
    flask.session.clear()
    return flask.redirect(flask.url_for('homepage'))


# Used to decorate methods that require authentication.
def requires_auth(f):
    """Wrapper function to prompt user to authenticate."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'access_token' not in flask.session:
            # Redirect to Login page
            return flask.redirect('/login')
        if not MSGRAPH.authorized:
            return flask.redirect('/login')
        if flask.session["token_expires_in"] < datetime.datetime.now():
            # If the access token is expired, require the user to login again
            return flask.redirect('/login')
        return f(*args, **kwargs)
    return decorated


@APP.route('/GetMyEmailAddress')
@requires_auth
def get_my_email_address():
    """Make Rest API call to graph for current users email"""
    flask.session['VIEW_DATA'].clear()  # reset data passed to the Graph.html
    base_url = config.RESOURCE + config.API_VERSION + '/'
    user_profile = MSGRAPH.get(base_url + 'me', headers=request_headers()).json()
    if 'error' in user_profile:  # Access token has expired!
        # print(user_profile)
        if user_profile['error']['code'] == 'InvalidAuthenticationToken':
            return flask.redirect(flask.url_for('login'))
       
    flask.session['email'] = user_profile['userPrincipalName']
    flask.session['username'] = user_profile['displayName']
    return flask.redirect(flask.url_for('homepage'))


@APP.route('/GetAlerts', methods=['POST', 'GET'])
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
         
        filtered_alerts = get_alerts_from_graph()
        if b'' in filtered_alerts:
            print("Please Sign-in using a on.microsoft.com account for demo data")
            filtered_alerts = "Incorrect Tenant Account"
        elif 'error' in filtered_alerts:
            if filtered_alerts['error']['code'] == 'InvalidAuthenticationToken':

                return flask.redirect(flask.url_for('login'))

        flask.session['VIEW_DATA']['GetAlertResults'] = filtered_alerts
    return flask.redirect(flask.url_for('homepage'))


def get_alerts_from_graph():
    """Helper to Make Rest API call to graph by building the query"""
    base_url = config.SECURITYAPI_URL
    alert_data = flask.session['alertData']
    filtered_query = ""
    if 'AssignedToMe' in alert_data:
        filtered_query += "assignedTo eq '" + flask.session['email'] + "'"
    if not alert_data:
        flask.session['VIEW_DATA']['QueryDetails'] = "REST query: '" + base_url + 'alerts/?$top=5' + "'"
        return MSGRAPH.get(base_url + 'alerts/?$top=5', headers=request_headers()).json()
    else:
        filtered_query += build_filter_query(alert_data)
        filtered_query += '$top=' if (len(filtered_query) == 0) else '&$top='
        filtered_query += alert_data['Top']

    add_filter = ""
    if filtered_query != ("$top=" + alert_data['Top']):
        add_filter = '$filter='

    query = "alerts?" + add_filter + filtered_query
    flask.session['VIEW_DATA']['QueryDetails'] = query
    query = urllib.parse.quote(query, safe="/?$='&")  # cleans up the url
    return MSGRAPH.get(base_url + query, headers=request_headers()).json()


def build_filter_query(form):
    """ Creates the odata query string used in the API request. """
    filtered_query = ""
    if ('Category' in form and form['Category'] != "All"):
        filtered_query += 'category eq ' if (len(filtered_query) == 0) else ' and category eq '
        filtered_query += "'{}'".format(form['Category'])
    if ('Provider' in form and form['Provider'] != "All"):
        filtered_query += 'vendorInformation/provider eq ' if (len(filtered_query) == 0) else ' and vendorInformation/provider eq '
        filtered_query += "'{}'".format(form['Provider'])
    if ('Status' in form and form['Status'] != "All"):
        filtered_query += 'Status eq ' if (len(filtered_query) == 0) else ' and Status eq '
        filtered_query += "'{}'".format(form['Status'])
    if ('Severity' in form and form['Severity'] != "All"):
        filtered_query += 'Severity eq ' if (len(filtered_query) == 0) else ' and Severity eq '
        filtered_query += "'{}'".format(form['Severity'])
    if ('HostFqdn' in form and form['HostFqdn'] != ""):
        filtered_query += "hostStates/any(a:a/fqdn eq " if (len(filtered_query) == 0) else ' and hostStates/any(a:a/fqdn eq '
        filtered_query += "'{}')".format(form['HostFqdn'])
    if ('Upn' in form and form['Upn'] != ""):
        filtered_query += 'userStates/any(a:a/userPrincipalName eq ' if (len(filtered_query) == 0) else ' and userStates/any(a:a/userPrincipalName eq '
        filtered_query += "'{}')".format(form['Upn'])
    return filtered_query


@APP.route('/DisplayAlert/<alert_id>')
@requires_auth
def display_alert(alert_id):
    """Renders the alert page"""
    alert = get_alert_by_id(alert_id)
    json_alert = json.dumps(alert, sort_keys=True, indent=4, separators=(',', ': '))
    return flask.render_template('alert.html',
                                 Title="Alert Details",
                                 Year=datetime.date.today().strftime("%Y"),
                                 Alert=json_alert,
                                 AlertId=alert_id,
                                 Config=config)


def get_alert_by_id(alert_id):
    """Helper function to get a security alert by ID
    
    alertId      = The Alert ID to be updated

    Returns the response from Graph
    """
    base_url = config.SECURITYAPI_URL
    alert = MSGRAPH.get(base_url + 'alerts/' + alert_id, headers=request_headers()).json()
    if b'' in alert:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        alert = None
    elif 'error' in alert:
        alert = None
    elif '@odata.context' in alert:  # remove ODATA entity
        del alert['@odata.context']
    return alert


def update_security_alert(alert_id, new_data):
    """Helper to Update a security graph alert.

    alertId      = The Alert ID to be updated
    newData      = The json body of the PATCH rest call
    """
    base_url = config.SECURITYAPI_URL
    _ = MSGRAPH.patch(base_url + 'alerts/' + alert_id, json=new_data, headers=request_headers())
    return


def get_top_security_alert():
    """Helper to get the most recent security graph alert."""
    base_url = config.SECURITYAPI_URL
    most_recent_alert = MSGRAPH.get(base_url + 'alerts/?$top=1', headers=request_headers()).json()
    if b'' in most_recent_alert:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        most_recent_alert = None
    elif 'error' in most_recent_alert:
        most_recent_alert = None
    return most_recent_alert


def create_webhook_subscription(webhook_body):
    """Helper to create a webhook subscription."""
    base_url = config.RESOURCE
    subscription = MSGRAPH.post(base_url + config.SECURITYAPI_VERSION + '/subscriptions',
                                json=webhook_body,
                                headers=request_headers()).json()
    print("Create subscription response", subscription)
    if b'' in subscription:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        subscription = None
    elif 'error' in subscription:
        if subscription['error']['code'] == 'InvalidAuthenticationToken':
            return flask.redirect(flask.url_for('login'))
        if subscription['error']['message'] == 'Subscription validation request failed. Must respond with 200 OK to this request.':
            message = "<strong>Error:</strong> Please run 'ngrok' to allow the webhook notification service to access your app, then update the config.py file to the correct ngrok url."
            flask.flash(message, category='danger')
    else:
        message = '<strong>Success</strong> Webhook subscription created. Id: ' + subscription.get('id')
        flask.flash(message, category='success')
    return subscription


def update_webhook_subscription(subscription_id, webhook_body):
    """Helper to update a webhook subscription."""
    base_url = config.RESOURCE 
    subscription = MSGRAPH.patch(base_url + config.SECURITYAPI_VERSION + '/subscriptions/' + subscription_id,
                                 json=webhook_body,
                                 headers=request_headers()).json()
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
    return subscription


def get_webhook_subscriptions():
    """Helper to get all current webhook subscriptions for the application."""
    base_url = config.RESOURCE    
    # print("base_url", base_url) 
    subscriptions = MSGRAPH.get(base_url + config.SECURITYAPI_VERSION + '/subscriptions').json()
    print("Active subscriptions :", subscriptions)
    if b'' in subscriptions:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        subscriptions = None
    elif 'error' in subscriptions:
        if subscriptions['error']['code'] == 'InvalidAuthenticationToken':

            return flask.redirect(flask.url_for('login'))
    return subscriptions


@requires_auth
def get_secure_score():
    """Helper to get the $Top=1 secure scores."""
    base_url = config.RESOURCE + config.SECURESCORE_VERSION + '/security/'
    secure_scores = MSGRAPH.get(base_url + 'secureScores?$top=1').json()
    # print("Top 1 secure Score :", json.dumps(secure_scores, sort_keys=True, indent=4, separators=(',', ': ')))
    if b'' in secure_scores:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        secure_scores = None
    elif 'error' in secure_scores:
        secure_scores = None
    elif len(secure_scores.get('value')) > 0:
        secure_scores = secure_scores.get('value')[0]
    else:
        secure_scores = None
    return secure_scores


@requires_auth
def get_secure_score_control_profiles():
    """Helper to get all the secure score control profiles."""
    base_url = config.RESOURCE + config.SECURESCORE_VERSION + '/security/'
    secure_score_control_profiles = MSGRAPH.get(base_url + 'secureScoreControlProfiles').json()
    # print("secureScoreControlProfiles :", json.dumps(secure_score_control_profiles, sort_keys=True, indent=4, separators=(',', ': ')))
    if b'' in secure_score_control_profiles:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        secure_score_control_profiles = None
    elif 'error' in secure_score_control_profiles:
        secure_score_control_profiles = None
    elif len(secure_score_control_profiles.get('value')) > 0:
        secure_score_control_profiles = secure_score_control_profiles.get('value')
    else:
        secure_score_control_profiles = None
    return secure_score_control_profiles


def create_action(action_body):
    """Helper to create a security action."""
    base_url = config.RESOURCE
    action = MSGRAPH.post(base_url + config.SECURITYACTION_VERSION + '/security/securityActions',
                          json=action_body,
                          headers=request_headers()).json()
    print("Create action response", action)
    if b'' in action:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        action = None
    elif 'error' in action:
        if action['error']['code'] == 'InvalidAuthenticationToken':
            return flask.redirect(flask.url_for('login'))
    else:
        message = '<strong>Success</strong> action created. Id: ' + action.get('id')
        flask.flash(message, category='success')
    return action


def get_actions():
    """Helper to get all current actions invoked by the application."""
    base_url = config.RESOURCE    
    # print("base_url", base_url) 
    security_actions = MSGRAPH.get(base_url + config.SECURITYACTION_VERSION + '/security/securityActions').json()
    print("security_actions :", security_actions)
    if b'' in security_actions:
        print("Please Sign-in using a on.microsoft.com account for demo data")
        security_actions = None
    elif 'error' in security_actions:
        if security_actions['error']['code'] == 'InvalidAuthenticationToken':

            return flask.redirect(flask.url_for('login'))
    return security_actions


@APP.route('/SecureScore', methods=['GET'])
@requires_auth
def secure_score():
    """ Show the secure score page. """
    return flask.render_template('SecureScore.html',
                                 Title="Microsoft Graph Security API demo web application",
                                 Year=datetime.date.today().strftime("%Y"),
                                 ViewData=flask.session['VIEW_DATA'],
                                 Config=config)


@APP.route('/UpdateAlert', methods=['POST', 'GET'])
@requires_auth
def update_alert():
    """ Make Rest API call to security graph to update an alert """
    if flask.request.method == 'POST':
        flask.session.pop('UpdateAlertData', None)
        result = flask.request.form
        flask.session['VIEW_DATA'].clear()
        alert_data = {_: result[_] for _ in result}  # Iterate over html form POST from Graph.html
        if alert_data.get('AlertId'):  # Id form was not empty
            alert_data['AlertId'] = alert_data.get('AlertId').strip(' ')
        else:
            flask.session['VIEW_DATA']['UpdateAlertError'] = "Please enter valid alert Id"
            return flask.redirect(flask.url_for('homepage'))
        alert_id = alert_data['AlertId']
        old_alert = get_alert_by_id(alert_id)  # store old alert before updating it
        if not old_alert:  # alert not found
            flask.session['VIEW_DATA']['UpdateAlertError'] = "No alert matching this ID " + alert_id + " was found"
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
                new_comment = alert_data.get("Comments")
                comments.append(new_comment)
                properties_to_update["comments"] = comments
            # include the required vendor information in the body of the PATCH
            properties_to_update["vendorInformation"] = old_alert.get("vendorInformation")
            # update the alert
            update_security_alert(alert_id, properties_to_update)
            # make another call to graph to get the updated alert
            updated_alert = get_alert_by_id(alert_id)
            # store the alert to be rendered in the table in Graph.html
            flask.session['VIEW_DATA']['UpdateAlertResults'] = updated_alert
            flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query PATCH: '" \
                                                               + config.SECURITYAPI_URL \
                                                               + "alerts/" \
                                                               + alert_id \
                                                               + "'"
            flask.session['VIEW_DATA']['UpdateQueryBody'] = "Request Body: " \
                                                            + json.dumps(properties_to_update,
                                                                         sort_keys=True,
                                                                         indent=4,
                                                                         separators=(',', ': '))
        flask.session['UpdateAlertData'] = alert_data
    return flask.redirect(flask.url_for('homepage'))


@APP.route('/Subscribe', methods=['POST', 'GET'])
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

            active_subscriptions = get_webhook_subscriptions()  # Check subscriptions to prevent repeat
            expiration_date_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            old_sub = None
            if len(active_subscriptions) > 0:
                for sub in active_subscriptions.get('value'):
                    if sub.get('resource') == webhook_body['resource']:
                        print("repeated resource")
                        old_sub = sub
                        break
            if old_sub:  # PATCH the current webhook subscription instead of creating a duplicate subscription
                webhook_body = {}
                webhook_body['expirationDateTime'] = expiration_date_time.isoformat() + "Z"
                response = update_webhook_subscription(old_sub.get("id"), webhook_body)
                if response:
                    print("PATCH response: ", response)
                    flask.session['VIEW_DATA']["webhook_sub"] = [response]
                    flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query PATCH: '" \
                                                                       + config.RESOURCE \
                                                                       + config.SECURITYAPI_VERSION \
                                                                       + "/subscriptions/" \
                                                                       + old_sub.get("id") \
                                                                       + "'"
                    flask.session['VIEW_DATA']['UpdateQueryBody'] = "Request Body: " \
                                                                    + json.dumps(webhook_body,
                                                                                 sort_keys=True,
                                                                                 indent=4,
                                                                                 separators=(',', ': '))
            else:
                webhook_body['expirationDateTime'] = expiration_date_time.isoformat() + "Z"
                print('expirationDateTime', webhook_body['expirationDateTime'])
                print('webhook_body', webhook_body)
                response = create_webhook_subscription(webhook_body)
                if response:
                    print("POST response: ", response)
                    flask.session['VIEW_DATA']["webhook_sub"] = [response]
                    flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query POST: '" \
                                                                       + config.RESOURCE \
                                                                       + config.SECURITYAPI_VERSION \
                                                                       + "/subscriptions'"
                    flask.session['VIEW_DATA']['UpdateQueryBody'] = "Request Body: " \
                                                                    + json.dumps(webhook_body,
                                                                                 sort_keys=True,
                                                                                 indent=4,
                                                                                 separators=(',', ': '))

    if flask.request.method == 'GET':
        flask.session['VIEW_DATA'].clear()
        active_subscriptions = get_webhook_subscriptions()
        if active_subscriptions:
                flask.session['VIEW_DATA']["webhook_sub"] = active_subscriptions.get('value')
                flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query GET: '" \
                                                                   + config.RESOURCE \
                                                                   + config.SECURITYAPI_VERSION \
                                                                   + "/subscriptions'"

    return flask.redirect(flask.url_for('homepage'))


@APP.route('/Actions', methods=['POST', 'GET'])
@requires_auth
def actions():
    if flask.request.method == 'POST':
        flask.session['VIEW_DATA'].clear()
        action_form = {}
        for key in flask.request.form:
            action_form[key] = flask.request.form[key]
        flask.session['VIEW_DATA']['ActionForm'] = action_form
        # print("action_form : ", action_form)
        action_body = {}
        action_body['name'] = action_form.get("SelectAction")
        action_body['actionReason'] = action_form.get("reason")
        _parameter = {}
        _parameter['name'] = action_form.get("propertyName")
        _parameter['value'] = action_form.get("propertyValue")
        action_body['parameters'] = [_parameter]
        _provider = action_form.get("Provider")
        action_body['vendorInformation'] = flask.session['provider_map'].get(_provider)

        print('action_body', action_body)
        response = create_action(action_body)
        if response:
            print("POST response: ", response)
            flask.session['VIEW_DATA']["action_created"] = [response]
            flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query POST: '" \
                                                               + config.RESOURCE \
                                                               + config.SECURITYACTION_VERSION \
                                                               + "/security/securityActions'"
            flask.session['VIEW_DATA']['UpdateQueryBody'] = "Request Body: " + json.dumps(action_body,
                                                                                          sort_keys=True,
                                                                                          indent=4,
                                                                                          separators=(',', ': '))

    if flask.request.method == 'GET':
        flask.session['VIEW_DATA'].clear()
        _actions = get_actions()
        if _actions:
                flask.session['VIEW_DATA']["action_created"] = _actions.get('value')
                flask.session['VIEW_DATA']['UpdateQueryDetails'] = "REST query GET: '" \
                                                                   + config.RESOURCE \
                                                                   + config.SECURITYACTION_VERSION \
                                                                   + "/securityActions'"

    return flask.redirect(flask.url_for('homepage'))


@APP.route('/listen', methods=['POST', 'GET'])
def listen():
    if flask.request.method == 'POST':
        validation_token = flask.request.args.get('validationToken', '')
        if validation_token != '':
            return flask.make_response(validation_token, 200)
        else:
            notification = flask.request.get_json()
            print('notification_received :', notification)
            if notification['value'] and len(notification['value']) > 0:
                sess = notification['value'][0].get('clientState')
                if sess:
                    SOCKETIO.emit("notification_received", notification, namespace='/listen')

            return flask.make_response('', 202)

    if flask.request.method == 'GET': 
        return flask.render_template('notification.html', Title="Microsoft Security Graph API demo web application",
                                     Year=datetime.date.today().strftime("%Y"))


@SOCKETIO.on('connect', namespace='/listen')
def test_connect():
    print("connected")


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

    SOCKETIO.run(APP)
