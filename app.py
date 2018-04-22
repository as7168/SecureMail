#!usr/bin/env python
from flask import Flask, request, render_template, url_for, redirect

app = Flask(__name__, template_folder='templates')
user = ''
passw = ''

@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		#print 'inpost'
		user = request.form['uname'].strip()
		password = request.form['pswd'].strip()
		print user
		print password
		return redirect(url_for('index', user=user, pas=password))
	else:
		return render_template('login.html')


@app.route('/index', methods=['GET', 'POST'])
def index():
	print 'in index'
	print request.args['user']
	if request.args['user'] is None or request.args['pas'] is None:
		return redirect(url_for('login'))

	if request.method == 'POST':
		send_to = request.form['send_to'].strip()
		key = request.form['key'].strip()
		subj = request.form['subject'].strip()
		body = request.form['body'].strip()
		print send_to, key, subj, body

	return render_template('index.html', user=request.args['user'])




if __name__ == '__main__':
	app.run(debug=True)
