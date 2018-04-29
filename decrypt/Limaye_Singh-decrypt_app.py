__author__ = 'Amandeep'

#!usr/bin/env python
from random import randint
from flask import Flask, request, render_template, url_for, redirect, session
import imaplib
from SecureEmail import SecureEmail_func
import base64
from html.parser import HTMLParser

# Initialize the app
app = Flask(__name__, template_folder='templates')

# Initializer the server
server = None

# Login page
@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		global server
		#print 'inpost'
		# Get the username and password from the HTML form
		user = request.form['uname'].strip()
		password = request.form['pswd'].strip()
		# Get the email provider and get its server and port
		mail_server, port = get_mail_server_and_port(user.split('@')[1])
		# If the email provider is not supported go back to login page
		if mail_server is None:
			return redirect(url_for('login'))
		# Make sure someone is not already logged in
		try:
			server.quit()
		except:
			pass
		# Connect to the imap email server
		server = imaplib.IMAP4_SSL(mail_server, port)
		# Login to the server
		try:
			server.login(user, password)
			server.select('INBOX')
		except:
			return 'Authentication Error! Try Logging in again'
		# If successfull Login, set the session with the username and redirect to index page
		session['username'] = user
		return redirect(url_for('index', user=user))
	else:
		return render_template('login.html')

# Page to retrieve emails
@app.route('/index', methods=['GET', 'POST'])
def index():
	if request.method == 'POST':
		global server
		#print 'in post'
		# If logged in, get sender's email address and subject of the email you want to retrieve
		if 'username' in session:
			from_ = request.form['from'].strip()
			subj = request.form['subject'].strip()
			# form imap query to search the email
			query = '(FROM "'+from_+'" SUBJECT "'+subj+'")'
			# get the uids for the emails corresponding to the search query
			result, data = server.uid('search', None, query)
			print (result)
			print (data)
			# If the search was successfull, return the uids, else go back to search page
			if result == 'OK':
				return redirect(url_for('views', data=data[0]))
			else:
				return render_template('decrypt_index.html', user=request.args['user'])
			#print send_to, key, subj, body
		else:
			# If not logged in redirect to login page
			return redirect(url_for('login'))
	
	#print request.args['user']
	# If logged in then give the user the search email page (decrypt_index.html)
	if request.args['user'] is not None:
		if 'username' in session:
			if session['username'] == request.args['user']:
				return render_template('decrypt_index.html', user=request.args['user'])
			else:
				session.pop('username')
	return redirect(url_for('login'))

# Page that displays uids of all the emails corresponding to the search query
@app.route('/views', methods=['GET', 'POST'])
def views():
	# If logged in get the uids and display them as buttons
	if 'username' in session:
		uids = request.args['data'].split()
		# If a button is pressed, redirect to view with the corresponding uid and display that specific email
		if request.method == 'POST':
			print (request.form['submit'])
			return redirect(url_for('view', uid=request.form['submit']))
		return render_template('views.html', user = session['username'], uids=uids)
	else:
		return redirect(url_for('login'))


@app.route('/view', methods=['GET'])
def view():
	#decryt data here
	# If logged in, display the email
	if 'username' in session:
		global server
		uid = request.args['uid']
		print (uid)
		# Fetch the email with uid
		result, data = server.uid('fetch', uid, '(RFC822)')
		#print(data)
		# If retrieved the data successfully
		if result == 'OK':
			# Parsing data
			string_to_search = b'.com\r\nTo: '+session['username'].encode()
			ind = data[0][1].find(string_to_search)+len(string_to_search)
			# Get the ciphertext from the email
			ciphertext = data[0][1][ind:].strip()
			# Decrypt the email
			plaintext = SecureEmail_func(2, True, base64.b64decode(ciphertext))
			# Bytes to string
			text = plaintext.decode()
			return render_template('view.html', body = text, user=session['username'])
	else:
		return redirect(url_for('login'))

# Logs out the user
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

# Helper function to get the smtp server url and port 
# Supported email providers at the moment: gmail, yahoo
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
