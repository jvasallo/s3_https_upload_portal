#!/usr/bin/env python

import os
import sys
import argparse
import logging
import base64
import urllib2
import json
import flask
from flask import Flask
from flask import render_template
from flask import request
from jinja2 import Environment
from jinja2 import FileSystemLoader
from flask_sslify import SSLify
import flask_login
import bcrypt

from datetime import datetime
from datetime import timedelta
from libs.utils import gen_policy
from libs.utils import upload_s3
from libs.utils import sign_policy
from libs.utils import valid_name
from libs.utils import get_s3_files
from libs.utils import get_s3_files_table
from libs.utils import get_temp_s3_url
from libs.utils import setup_logging
from libs.utils import ztree_files
from libs.utils import get_user
from libs.utils import get_env_creds
from libs.utils import create_folder_and_lifecycle
from libs.utils import init
from libs.utils import dt_to_string


application = app = flask.Flask(__name__)
# sslify = SSLify(app)
init()
PREFIX = 'uploads/'  # name of uploads folder in bucket. must end in /

# Login mamanger

app.secret_key = 'qwerty1234567'
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

ausers = {'fg-support': {'pw': '$2b$12$Y6p08kLzs02Kt9LTIo2jV.0CXpaWJyxTf9SUmB3eTOig7WTofqt0W'},
          'fg-field':   {'pw': '$2b$12$Y6p08kLzs02Kt9LTIo2jV.0CXpaWJyxTf9SUmB3eTOig7WTofqt0W'}}

class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(uname):
    if uname not in ausers:
        return

    user = User()
    user.id = uname
    return user


# @login_manager.request_loader
# def request_loader(request):
#    uname = request.form.get('uname')
#    print 'fromform', uname
#    if uname not in ausers:
#        return
#
#    user = User()
#    user.id = uname
#
    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
#    lhash = bcrypt.hashpw(request.form['pw'].encode('utf-8'), bcrypt.gensalt())
#    print request.form['pw'].encode('utf-8')
#    user.is_authenticated = bcrypt.hashpw(request.form['pw'].encode('utf-8'), lhash) == lhash
#
#    return user

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('loginerror.html',
                           message='Unauthorized: this page requires a valid login',
                           ua=False)

# -------------------    end of login mamanger 

@app.route('/logout')
def logout():
    cuser = flask_login.current_user
    if cuser.is_authenticated : 
        flask_login.logout_user()
       
    return render_template('index_login.html', ua = False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':
        return render_template('index_login.html', ua = False)

    uname = flask.request.form['uname']
    if uname not in ausers:
        return render_template('loginerror.html', message='Login Incorrect', ua = False)

    matched = bcrypt.hashpw(flask.request.form['pw'].encode('utf-8'), ausers[uname]['pw']) == ausers[uname]['pw']
    if matched :
        user = User()
        user.id = uname
        flask_login.login_user(user,remember=False)
        # return flask.redirect(flask.url_for('/', _scheme="https", _external=True))
        return render_template('index.html', ua = True)

    return render_template('loginerror.html', message='Login Incorrect', ua = False )


@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message='Page Not Found')


@app.route('/ztreeapi')
@flask_login.login_required
def ztreeapi():
    if not request.is_xhr:
        return ''

    try:
        folder = request.args['folder']
    except:
        folder = ''

    ztree = ztree_files(prefix=PREFIX + folder)
    return json.dumps(ztree)


@app.route('/files')
@flask_login.login_required
def list_files():
    try:
        folder = request.args['folder']
    except:
        folder = ''

    try:
        view = request.args['view']
    except:
        view = None

    if view == 'tree':
        return render_template('file_list.html',
                               folder=folder, ua = True)
    else:
        try:
            # get the file listing
            s3_files = get_s3_files_table(prefix=PREFIX + folder)
        except:
            # return render_template('error.html',
            #                      message='Error %s' % str(sys.exc_info()), ua = True)
            return render_template('file_list_table.html',
                               files=s3_files,
                               folder=folder,
                               d2s=dt_to_string, ua = True)


@app.route('/',methods=['GET', 'POST'])
def index():
    if flask_login.current_user.is_authenticated: 
        return render_template('index.html', ua = True )
    else:
        return render_template('index_login.html', ua = False)

@app.route('/loginvalidate', methods=['POST'])
def login_validate():
    ua = False
    uname = flask.request.form['uname']
    if uname not in ausers:
        return render_template('loginerror.html', ua, message='Login Incorrect')

    matched = bcrypt.hashpw(flask.request.form['pw'].encode('utf-8'), ausers[uname]['pw']) == ausers[uname]['pw']
    if matched :
        user = User()
        user.id = uname
        flask_login.login_user(user,remember=False)
        ua = True
        # return flask.redirect(flask.url_for('/', _scheme="https", _external=True))
        return render_template('index.html', ua )

    return render_template('loginerror.html', ua, message='Login Incorrect')


@app.route('/bucketparams')
@flask_login.login_required
def form_params():
    now = datetime.now()
    defaultdate = (now + timedelta(days=180)).isoformat()[:10]
    return render_template('formgen.html',
                           defaultdate=defaultdate, ua = True )


@app.route('/info')
def info():
    ua = flask_login.current_user.is_authenticated
    return render_template('info.html', ua=flask_login.current_user.is_authenticated )


@app.route('/gendl')
@flask_login.login_required
def generate_dl_link():
    filelist = []
    for i in get_s3_files('uploads'):
        filelist.append(i[0])
    try:
        keyname = request.args['keyname']
       # keyname = base64.decodestring(urllib2.unquote(keyname))
        keyname = urllib2.unquote(keyname)
        print 'dendl :' + keyname
        version_id = request.args['version']
        version_id = base64.decodestring(urllib2.unquote(version_id))
        assert keyname in filelist
        dl_url = get_temp_s3_url(keyname, version_id)
        filename = keyname.split('/')[-1]
        logging.info('User [%s] generated a url for %s' % (get_user(request),
                                                           filename))
        return render_template('s3_redir_dl.html',
                               url=dl_url,
                               keyname=keyname,
                               filename=filename, ua = True)

    except:
        return render_template('error.html',
                               message='Invalid Parameters %s'
                                       % str(sys.exc_info()), ua = True)


@app.route('/generate_form', methods=['POST'])
@flask_login.login_required
def generate_form():
    ua = True

    try:
        bucket_name = os.environ['BUCKET']
        access_key, secret_key = get_env_creds()
    except:
        return render_template('error.html', ua = True, 
                               message='Error obtaining valid creds: %s'
                                       % str(sys.exc_info()))

    try:
        lc_expiration = request.form['lifecycle']
        lc_expiration = int(lc_expiration)
        assert lc_expiration <= 180
    except:
        return render_template('error.html', ua = True, 
                               message='Invalid Lifecycle Duration')

    try:
        exp = request.form['exp']
        exp = datetime.strptime(exp, '%Y-%m-%d').isoformat() + 'Z'
    except:
        return render_template('error.html', ua = True,
                               message='Invalid Expiration Date')

    try:
        maxupload = request.form['maxupload']
        max_megs = int(maxupload) / (1024 * 1024)
    except:
        return render_template('error.html', ua = True,
                               message='Invalid File Size')

    try:
        directory = request.form['directory']
        assert valid_name(directory)
        assert directory != ''
        directory = 'uploads/' + directory
    except:
        return render_template('error.html', ua = True, 
                               message='Invalid/Empty Name for \
                               Customer/Identifier. \'A-Z\', \'0-9\',\
                                \'-\' and \'_\' only.')

    try:
        notes = request.form['notes']
    except:
        notes = ''

    try:
        policy = gen_policy(bucket_name   = bucket_name,
                            expiration    = exp,
                            max_byte_size = maxupload,
                            directory     = directory)
    except:
        return render_template('error.html', ua = True,
                               message='Error Gen Policy: %s'
                                       % str(sys.exc_info()))

    try:
        signature, policy = sign_policy(policy=policy,
                                        secret=secret_key)
    except:
        return render_template('error.html', ua = True,
                               message='Error Sign Policy: %s' % str(sys.exc_info()))

    try:
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('upload.html')
        html = template.render(bucket_name=bucket_name,
                               access_key=access_key,
                               policy=policy,
                               signature=signature,
                               max_in_megs=max_megs,
                               notes=notes,
                               directory=directory)
    except:
        return render_template('error.html', ua = True,
                               message='Error rendering template: %s' % str(sys.exc_info()))

    try:
        create_folder_and_lifecycle(bucket_name=bucket_name,
                                    directory=directory,
                                    expiration=lc_expiration)
    except:
        return render_template('error.html', ua = True,
                               message='Error setting lifecycle: %s'
                                       % str(sys.exc_info()))

    try:
        url = upload_s3(contents=html,
                        bucket_name=bucket_name)
    except:
        return render_template('error.html', ua = True, 
                               message='Error uploading to s3: %s' % str(sys.exc_info()))

    if url is None:
        return render_template('error.html', ua = True,
                               message='Could not generate URL. Check Logs')

    # strip signature from url; we dont need since the form is public
    url = url.split('?')[0]

    logging.info('User [%s] generated a form called %s'
                 % (get_user(request), directory))
    portal = directory[len(PREFIX):]
    return render_template('done.html',
                           url=url,
                           bucket_name=bucket_name,
                           access_key=access_key,
                           expiration=exp,
                           policy=policy,
                           signature=signature,
                           directory=directory,
                           url_root=request.url_root,
                           portal=portal, 
                           ua = True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTPS Upload')
    args = parser.parse_args()

    logging = setup_logging()
    # application.run(host='0.0.0.0', debug=True, ssl_context=('cert.pem', 'key.pem'))
    application.run(host='0.0.0.0')