import requests, time, base64
from flask import Flask, render_template, url_for, redirect, session, json, jsonify
from flask_oidc import OpenIDConnect


def getCurrentTime():
    t = time.localtime()
    current_time = time.strftime("%D %H:%M:%S", t)
    return current_time

def updateSchema():
    t = getCurrentTime()
    url = "{Domain URL}"
    headers = '{"Accept": "application/json", "Content-Type": "application/json", "Authorization": "SSWS {API KEY}"}'
    payload = '{"profile": {"lastLoginDate": "%s"}}' % (t)
    r = requests.post("{Domain URL}", data=payload, headers=headers)

