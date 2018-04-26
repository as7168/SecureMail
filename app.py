#!usr/bin/env python
from random import randint
from flask import Flask, request, render_template, url_for, redirect, session
from flask_mail import Mail, Message
import requests.packages.urllib3.contrib.pyopenssl

app = Flask(__name__, template_folder='templates')

mail_server = 'smtp.gmail.com'
usr = 'sainiboy.aman@gmail.com'
pswd = '789512364'
app.config.update(
			MAIL_SERVER= mail_server,
			MAIL_USERNAME=usr,
			MAIL_PASSWORD=pswd,
			MAIL_PORT = 465
		)
mail = Mail(app)

@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		print 'inpost'
		user = request.form['uname'].strip()
		password = request.form['pswd'].strip()
		session['username'] = user
		mail_server = get_mail_server_and_port(user.split('@')[1])
		return redirect(url_for('index', user=user))
	else:
		return render_template('login.html')


@app.route('/index', methods=['GET', 'POST'])
def index():
	if request.method == 'POST':
		print 'in post'
		print app.config['MAIL_USERNAME']
		print app.config['MAIL_PASSWORD']
		print app.config['MAIL_PORT']
		send_to = request.form['send_to'].strip()
		key = request.form['key'].strip()
		subj = request.form['subject'].strip()
		body = request.form['body'].strip()
		#recipient_list = recipient.split(",")
		msg = Message(subj, sender=request.args['user'], recipients=send_to)
		msg.body = body
		mail.send(msg)
		print send_to, key, subj, body
	
	#print request.args['user']
	if request.args['user'] is not None:
		if 'username' in session:
			if session['username'] == request.args['user']:
				return render_template('index.html', user=request.args['user'])
			else:
				session.pop('username')

	return redirect(url_for('login'))


def get_mail_server_and_port(mail_server):
	if mail_server == 'yahoo.com':
		return 'smtp.mail.yahoo.com'
	if mail_server == 'gmail.com':
		return 'smtp.gmail.com'
	if mail_server == 'outlook.com':
		return 'smtp-mail.outlook.com'

if __name__ == '__main__':
	app.secret_key = str(randint(1, 1000000))
	app.debug = True
	app.run()
