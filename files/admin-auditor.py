#!/usr/bin/env python

import sys
import os
import re
from datetime import datetime
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client

auth = v3.Password(
    auth_url=os.environ['OS_AUTH_URL'],
    username=os.environ['OS_USERNAME'],
    password=os.environ['OS_PASSWORD'],
    project_name=os.environ['OS_PROJECT_NAME'],
    user_domain_name=os.environ['OS_USER_DOMAIN_NAME'],
    project_domain_name=os.environ['OS_PROJECT_DOMAIN_NAME']
)
sess = session.Session(auth=auth)
keystone = client.Client(session=sess)

for i in keystone.roles.list():
    if i.name == 'admin':
        admin_role_uuid = i.id
        break

admins = []


def get_fields(f, us):
    # Helper function to quickly find objects by fields
    return [getattr(x, f) for x in us]

for i in keystone.role_assignments.list():
    if i.role['id'] == admin_role_uuid:
        user = keystone.users.get(i.user['id'])
        if user.id not in get_fields('id', admins):
            admins.append(user)

# Decrease lookup time by caching admin uuids and names
admin_uuids = get_fields('id', admins)
admin_names = get_fields('name', admins)


def remove_prefix(text, prefix):
    return text[text.startswith(prefix) and len(prefix):]


def process_line(line):
    # Takes a log line from an openstack service and filters out
    # lines that are uninteresting
    fields = line.split()

    # We don't care about problems in this context
    try:
        if fields[3] in ['WARNING', 'ERROR', 'CRITICAL']:
            return
    except IndexError as e:
        return

    # We only care about admin actions
    try:
        if fields[6] not in admin_uuids:
            return
    except IndexError as e:
        return

    # Oslo and raw wsgi alerts can't be called 
    # directly and are guaranteed irrelevant.
    try:
        for f in ["oslo", "eventlet.wsgi.server"]:
            if f in fields[4]:
                return
    except IndexError as e:
        return

    # Exclude api hits that are read only. Most notably this means removing
    # GET and OPTIONS. This has the added benefit of capturing only actual
    # requests and not just mod_wsgi talking to itself.
    try:
        http_verbs = ['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'TRACE',
                         'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY',
                         'MOVE', 'LOCK', 'UNLOCK', 'VERSION-CONTROL',
                         'REPORT', 'CHECKOUT', 'CHECKIN' 'UNCHECKOUT',
                         'MKWORKSPACE', 'UPDATE', 'LABEL', 'MERGE',
                         'BASELINE-CONTROL', 'MKACTIVITY', 'ORDERPATCH',
                         'ACL', 'PATCH', 'SEARCH']

        # We have to search the entire line because of the field existing
        # in multiple places. Keystone has a different format than all 
        # other services because why not.
        found_verb = False
        for verb in http_verbs:
            if verb in line:
                found_verb = True
                break
        if not found_verb:
            return
    except IndexError as e:
        return

    # We don't care if service accounts use their own service apis
    try:
        admin_name = [n.name for n in admins if n.id == fields[6]][0]
        if admin_name in fields[4]:
            return
    except IndexError as e:
        return

    # All lines so far should be logged, but only those matching
    # lines matching these regexes need to be reviewed. We match
    # regex on the entire line.
    try:
        regexes = [
            '.*'    # matches everything 
        ] 
        for regex in regexes:
            result = re.match(regex, line)
            if result is not None:
                fields.append('LOG_ANOMALY')
    except IndexError as e:
        return

    # print lines not caught by a filter
    # Since we can't guarantee structure of every line, we have to add
    # a keyed field so splunk can pull it out. This is going to be
    # the "collected" date (i.e., the time the script was run)
    fields = ["SPLUNK_" + str(datetime.now()) + "_SPLUNK] + fields
    print(' '.join(fields))


if __name__ == "__main__":
    logfiles = sys.argv[1:]
    for file in logfiles:
        with open(file, "r") as f:
            for line in f:
                process_line(line)

