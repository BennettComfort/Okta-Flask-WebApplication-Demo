import requests, time, base64
from flask import Flask, render_template, url_for, redirect, session, json, jsonify
from flask_oidc import OpenIDConnect


headers = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": "SSWS 00KDXEg5_pknkU55DeGnH1w8-KoSUF0UF-wsNvBad8"}
url = 'https://dev-302835.okta.com/api/v1/users/00u735ijDlZM5P1ti5d5'
payload = '{"profile": {"GitHub": "https://github.com/bennettcomfort"}}'
r = requests.post(url, data=payload, headers=headers)

print(r)