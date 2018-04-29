#!usr/bin/env python
from random import randint
from flask import Flask, request, render_template, url_for, redirect, session
import imaplib

app = Flask(__name__, template_folder='templates')

server = None

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
		server = imaplib.IMAP4_SSL(mail_server, port)
		try:
			server.login(user, password)
			server.select('INBOX')
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
			from_ = request.form['from'].strip()
			subj = request.form['subject'].strip()
			query = '(FROM "'+from_+'" SUBJECT "'+subj+'")'
			result, data = server.uid('search', None, query)
			print result
			print data
			if result == 'OK':
				return redirect(url_for('views', data=data[0]))
			else:
				return render_template('decrypt_index.html', user=request.args['user'])
			#print send_to, key, subj, body
		else:
			return redirect(url_for('login'))
	
	#print request.args['user']
	if request.args['user'] is not None:
		if 'username' in session:
			if session['username'] == request.args['user']:
				return render_template('decrypt_index.html', user=request.args['user'])
			else:
				session.pop('username')

	return redirect(url_for('login'))

@app.route('/views', methods=['GET', 'POST'])
def views():
	if 'username' in session:
		uids = request.args['data'].split()
		if request.method == 'POST':
			print request.form['submit']
			return redirect(url_for('view', uid=request.form['submit']))
			
		return render_template('views.html', user = session['username'], uids=uids)
	else:
		return redirect(url_for('login'))


@app.route('/view', methods=['GET'])
def view():
	#decryt data here
	if 'username' in session:
		global server
		uid = request.args['uid']
		print uid
		result, data = server.uid('fetch', int(uid), '(RFC822)')
		if result == 'OK':
			#print data
			return data[0]
	else:
		return redirect(url_for('login'))


@app.route('/logout', methods=['GET'])
def logout():
	global server
	if len(session) != 0:
		user1 = ''
		password1 = ''
		session.pop('username')
		try:
			server.logout()
		except:
			pass
	#return 'You have logged out'
	return redirect(url_for('login'))


def get_mail_server_and_port(mail_server):
	if mail_server == 'yahoo.com':
		return 'imap.mail.yahoo.com', 993
	if mail_server == 'gmail.com':
		return 'imap.gmail.com', 993
	else:
		return None, None

if __name__ == '__main__':
	app.secret_key = str(randint(1, 1000000))
	app.debug = True
	app.run()
