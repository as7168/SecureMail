#!usr/bin/env python
from random import randint
from flask import Flask, request, render_template, url_for, redirect, session
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__, template_folder='templates')

server = smtplib.SMTP_SSL()

@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		global server
		#print 'inpost'
		user = request.form['uname'].strip()
		password = request.form['pswd'].strip()
		mail_server, port = get_mail_server_and_port(user.split('@')[1])
		if mail_server is None:
			return redirect(url_for('login'))
		try:
			server.quit()
		except:
			pass
		server.connect(mail_server, port)
		try:
			server.login(user, password)
		except:
			return 'Authentication Error! Try Logging in again'
		session['username'] = user
		return redirect(url_for('index', user=user))
	else:
		return render_template('login.html')


@app.route('/index', methods=['GET', 'POST'])
def index():
	if request.method == 'POST':
		global server
		#print 'in post'
		if 'username' in session:
			send_to = request.form['send_to'].strip()
			key = request.form['key'].strip()
			subj = request.form['subject'].strip()
			body = request.form['body'].strip()
			send_to_list = send_to.split(",")
			try:
				server.ehlo()
			except:
				return 'Something went wrong! Try logging in again'
			print send_to_list
			for i in send_to_list:
				msg = MIMEText(body)
				msg['Subject'] = subj
				msg['From'] = request.args['user']
				msg['To'] = i
				server.sendmail(request.args['user'], i, msg.as_string())
			#print send_to, key, subj, body
		else:
			return redirect(url_for('login'))
	
	#print request.args['user']
	if request.args['user'] is not None:
		if 'username' in session:
			if session['username'] == request.args['user']:
				return render_template('index.html', user=request.args['user'])
			else:
				session.pop('username')

	return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
def logout():
	global server
	if len(session) != 0:
		user1 = ''
		password1 = ''
		session.pop('username')
		try:
			server.quit()
		except:
			pass
	#return 'You have logged out'
	return redirect(url_for('login'))


def get_mail_server_and_port(mail_server):
	if mail_server == 'yahoo.com':
		return 'smtp.mail.yahoo.com', 465
	if mail_server == 'gmail.com':
		return 'smtp.gmail.com', 465
	else:
		return None, None

if __name__ == '__main__':
	app.secret_key = str(randint(1, 1000000))
	app.debug = True
	app.run()
