#!usr/bin/env python
from flask import Flask

app = Flask(__name__)

@app.route('/')
def route():
	return 'Hello World'



if __name__ == '__main__':
	app.run(debug=True)
