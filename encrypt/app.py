#!usr/bin/env python
from random import randint
from flask import Flask, request, render_template, url_for, redirect, session
import smtplib
from email.mime.text import MIMEText
from SecureEmail import SecureEmail_func

# Initialize the app and set the default templates folder
app = Flask(__name__, template_folder='templates')

# Initialize the smtp server
server = smtplib.SMTP_SSL()

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
		# Connect to the smtp server
		server.connect(mail_server, port)
		# Login to the server using username and password entered
		# If the credentials are wrong prompt it
		try:
			server.login(user, password)
		except:
			return 'Authentication Error! Try Logging in again'
		# If successfull Login, set the session with the username and redirect to index page
		session['username'] = user
		return redirect(url_for('index', user=user))
	else:
		return render_template('login.html')

# Page to send the emails
@app.route('/index', methods=['GET', 'POST'])
def index():
	if request.method == 'POST':
		global server
		#print 'in post'
		# If logged in, get recipient address/addresses, subject of email and body
		if 'username' in session:
			send_to = request.form['send_to'].strip()
			subj = request.form['subject'].strip()
			body = request.form['body'].strip()
			send_to_list = send_to.split(",")
			print(body)
			# Encrypt the body
			try:
				did_it_encrypt, ciphertext = SecureEmail_func(1, False, body.encode('utf-8'))
			# If encryption was successfull then move on otherwise prompt it
			except:
				return 'Encryption Failed! \n\n Check if you have the public and private keys present in the folder.\n\nPlease try again'
			# Send hello to server- Gmail requires it
			try:
				server.ehlo()
			except:
				return 'Something went wrong! Try logging in again'
			#print(send_to_list)
			# Send emails to all the recipients one by one
			for i in send_to_list:
				msg = MIMEText(ciphertext, _charset='utf-8')
				msg['Subject'] = subj
				msg['From'] = request.args['user']
				msg['To'] = i
				server.sendmail(request.args['user'], i, msg.as_string())
			#print send_to, key, subj, body
		else:
			return redirect(url_for('login'))
	
	#print request.args['user']
	# If logged in then give the user the sending email page (index.html)
	if request.args['user'] is not None:
		if 'username' in session:
			if session['username'] == request.args['user']:
				return render_template('index.html', user=request.args['user'])
			else:
				session.pop('username')

	# If not logged in, redirect back to login page
	return redirect(url_for('login'))

# Logout function
@app.route('/logout', methods=['GET'])
def logout():
	global server
	# If someone logged in, pop the session and log them out
	if 'username' in session:
		session.pop('username')
		# Also disconnect from smtp server
		try:
			server.quit()
		except:
			pass
	# Redirect to login page after logging out
	return redirect(url_for('login'))

# Helper function to get the smtp server url and port 
# Supported email providers at the moment: gmail, yahoo
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
	app.run(port=5999)
