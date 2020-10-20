import base64, time, requests, functions
from functions import getCurrentTime, updateSchema
from flask import Flask, render_template, url_for, redirect, session, json, jsonify, request, flash
from flask_oidc import OpenIDConnect

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': '{Secret KEY}',
    'OIDC_CLIENT_SECRETS': './client_secrets.json',
    'OIDC_DEBUG': True,
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_SCOPES': ["openid", "profile", "email", "groups", "address","default"],
    'OVERWRITE_REDIRECT_URI': '{DomainURL}/authorization-code/callback',
    'OIDC_CALLBACK_ROUTE': '/authorization-code/callback'
})

oidc = OpenIDConnect(app)

@app.route("/")
def home():
    if oidc.user_loggedin:
        t = getCurrentTime()
        userID = oidc.user_getfield('sub')
        name = oidc.user_getfield('email')
        url = '{DomainURL}/api/v1/users/%s' % (userID)
        headers = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": "SSWS {API-KEY}"}
        payload = '{"profile": {"lastLoginDate": "%s"}}' % (t)
        r = requests.post(url, data=payload, headers=headers)
        return render_template("home.html", oidc=oidc, name=name)
    else:
        return render_template("home.html", oidc=oidc)

@app.route("/login")
def login():
    bu = oidc.client_secrets['issuer'].split('/oauth2')[0]
    cid = oidc.client_secrets['client_id']
    destination = '{DomainURL}/profile'
    state = {
        'csrf_token': session['oidc_csrf_token'],
        'destination': oidc.extra_data_serializer.dumps(destination).decode('utf-8')
    }
    return render_template("login.html", oidc=oidc, baseUri=bu, clientId=cid, state=base64_to_str(state))

@app.route("/okta")
def okta():
    return redirect("{DomainURL}", code=302)

@app.route("/profile")
def profile():
    t = getCurrentTime()
    ID = oidc.user_getfield('sub')
    headers = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": "SSWS {API-KEY}"}
    url = '{DomainURL}/api/v1/users/%s' % (ID)
    
    # Make call to api for current user's last login time
    res = requests.get(url, headers=headers)
    y = json.loads(res.text)
    this = y["profile"]["lastLoginDate"]
    
    # Update the lastLoginTime POST api call
    payload = '{"profile": {"lastLoginDate": "%s"}}' % (t)
    r = requests.post(url, data=payload, headers=headers)
    
    info = oidc.user_getinfo(['email', 'name', 'sub', 'preferred_username'])
    return render_template("profile.html", profile=info, oidc=oidc, this=this)

@app.route("/logout", methods=["POST"])
def logout():
    oidc.logout()
    return redirect(url_for("home"))

@app.route("/")
def me():
    return jsonify({'response': 200, 'results': list(definitions.keys())})

@app.route('/', methods=['POST'])
def my_form_post():
    processed_text = request.form['text']
    name = oidc.user_getfield('email')
    userID = oidc.user_getfield('sub')
    url = '{DomainURL}/api/v1/users/%s' % (userID)
    headers = {"Accept": "application/json", "Content-Type": "application/json", "A8uthorization": "SSWS {API-KEY}"}
    payload = '{"profile": {"GitHub": "%s"}}' % (processed_text)
    r = requests.post(url, data=payload, headers=headers)
    return render_template("home.html", oidc=oidc, processed_text=processed_text, name=name)

def base64_to_str(data):
    return str(base64.b64encode(json.dumps(data).encode('utf-8')), 'utf-8')

if __name__ == '__main__':
   app.run(host="localhost", port=8080, debug=True)

