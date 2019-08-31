'''

StreamLabs and TurtleCoin integration system.
Made by Lucas Oberwager and the TurtleCoin devs.
Copyright 2019, TwitchTurtle and TurtleCoin devs

This file is part of TwitchTurtle.

	TwitchTurtle is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	TwitchTurtle is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with TwitchTurtle.  If not, see <https://www.gnu.org/licenses/>.

'''
from walletd import Walletd
from flask import Flask, abort, request, jsonify, g, url_for
from sqlalchemy.dialects.postgresql import UUID 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text as sa_text
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
			  as Serializer, BadSignature, SignatureExpired)
from streamlabs import Stream
from sqlalchemy_utils import UUIDType
import threading
import os
import requests
import random
import uuid
import string
import re, ast, binascii, json

# Get config data
with open('settings.json', 'r') as f:
    settings = json.load(f)

 
env = settings["current_env"] 


# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = settings[env]["flask"]["SECRET_KEY"]
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

rpc_password = settings[env]["turtle-service"]["rpc_password"]
rpc_host = settings[env]["turtle-service"]["rpc_host"]
rpc_port = settings[env]["turtle-service"]["rpc_port"]


walletd = Walletd(rpc_password, rpc_host, rpc_port)

# extensions
db = SQLAlchemy(app)
db.UUID = UUID
auth = HTTPBasicAuth()



class User(db.Model):
	# Initialize table of user accounts
        __tablename__ = 'users'
	id = db.Column(
                UUIDType(binary=False), 
                primary_key=True, 
                default=lambda:uuid.uuid4(), 
                nullable=False 
            )
        # Unique streamlabs identifier
	streamlabs_id = db.Column(db.String(32), index=True)
        # Streamlabs frontend username
	username = db.Column(db.String(32), index=True)
        # Coin address
	address = db.Column(db.String(99), index=True)
        # Streamlabs oauth2 tokens
	refresh_token = db.Column(db.String(99))
	access_token = db.Column(db.String(99))
        # Streamlabs expiry counter
	expires_on = db.Column(db.String(99))
        # Min amount needed to be donated, in USD, for alerts to get sent to Streamlabs
        # Even if there is a higher streamlabs min donation, it will not be registered
	minAlertNum = db.Column(db.Float(), default=0.0)

	def generate_auth_token(self, expiration=86400):
		s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
		return s.dumps({'id': self.streamlabs_id})

	def hash_password(self, password):
		self.password_hash = pwd_context.encrypt(password)

	def verify_password(self, password):
		return pwd_context.verify(password, self.password_hash)

	@staticmethod
	def verify_auth_token(token):
		s = Serializer(app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except SignatureExpired:
			return None    # valid token, but expired
		except BadSignature:
			return None    # invalid token
		user = User.query.filter_by(streamlabs_id=data['id']).first()
		return user

class Tipper(db.Model):
	# Second table of paymentID to extra mappings
        # This is used so users can either use the web interface and have a payment ID,
        # Or they can supply the data in the extra in their transaction
        __tablename__ = 'transactions'
	id = db.Column(
                UUIDType(binary=False), 
                primary_key=True, 
                default=lambda:uuid.uuid4(), 
                nullable=False 
            )
	paymentID = db.Column(db.String(64), index=True)
	extra = db.Column(db.String(310))

# Start async function to get new transactions
threading.Timer(1, Stream.searchForTransaction, args=[],).start() 
print('Started listener')


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

'''
    @def Used to login and create user accounts, called in the oauth2 process
'''
@app.route('/api/code', methods=['POST']) 
def new_user():
	code = request.json.get('code')
	if code is None:
            # Users must have a code    
	    return jsonify({'error': 'Missing code argument'}), 400

	response = Stream.getRefreshToken(code)

	access_token =  response[0]
	refresh_token = response[1]
	expires_on = response[2]

	if access_token is None or refresh_token is None:
            # Getting the refresh tokens failed for some reason
	    return jsonify({'error': 'invalid tokens'}), 400

	# Get username info
	url = "https://streamlabs.com/api/v1.0/user"
	querystring = {"access_token":access_token}
	Streamlabsuser = requests.request("GET", url, params=querystring)
	data = Streamlabsuser.json()
	vanityname = data['streamlabs']['display_name']
	streamlabs_id = data['streamlabs']['id']

	userExists = User.query.filter_by(streamlabs_id=streamlabs_id).first()
	if userExists is None:
                # User does not exist, create
		user = User(streamlabs_id = streamlabs_id)
		create_address = walletd.create_address()
		user.address = create_address['result']['address']
	else:
                # Welcome back, user
		user = User.query.filter_by(streamlabs_id=streamlabs_id).first()

        # Update user tokens  
	user.access_token= access_token
	user.refresh_token=refresh_token
	user.expires_on=expires_on
	user.username=vanityname.lower()


	if userExists:
                # User already exists, no need to add user 
		db.session.commit()
                return_code = 200
	else:
                # User does not already exist in the db, create
		db.session.add(user)
		db.session.commit()
                # HTTP return code 201 means created
                return_code = 201

        token = user.generate_auth_token(86400)
	return (jsonify({
                    'username': vanityname, 
                    'token': token.decode('ascii'), 
                    'address': user.address
                }), return_code)

@app.route('/api/status') # Get the block status of turtle-service (aka walletd)
def get_status():
	try:
		response = walletd.get_status()
	except requests.exceptions.RequestException as e:
		#print(e)
		return jsonify({'error': 'connection refused'}), 503
	nodeHeight = response['result']['knownBlockCount']
	walletHeight = response['result']['blockCount']
	json = {'synced': True, 'walletHeight': walletHeight, 'nodeHeight': nodeHeight}
	if (abs(nodeHeight-walletHeight) > 10 or nodeHeight < 10 or walletHeight < 10):
		json['synced'] = False 

	return jsonify(json)

@app.route('/api/address/<username>') # Get the address by suppliying username
def get_addr(username):
	username = username.lower()
	user = User.query.filter_by(username=username).first()
	if not user:
		return jsonify({'error': 'invalid user'}), 400
	return jsonify({'address': user.address, 'minDonation': user.minAlertNum})

@app.route('/api/user/<address>') # Get the username by suppliying address
def get_user_byaddr(address):
	user = User.query.filter_by(address=address).first()
	if not user:
		return jsonify({'error': 'invalid user'}), 400
	return jsonify({'user': user.username})

@app.route('/api/extra/<paymentID>') # Get the extra by suppliying paymentID
def get_extra(paymentID):
	tipper = Tipper.query.filter_by(paymentID=paymentID).first()
	if not tipper:
		return jsonify({'error': 'invalid paymentID'}), 400
	return jsonify({'extra': tipper.extra})

# Register a new payment ID to extra mapping for use in trtl.tv/<user>
@app.route('/api/tipper', methods=['POST']) 
def add_tipper():

	extra = request.json.get('extra')
	if extra is None:
		return jsonify({'error': 'Missing arguments'}), 400

	# Check if extra already exists
	TipperTable = Tipper.query.filter_by(extra=extra).first()
	if TipperTable:
		return jsonify({'paymentID':TipperTable.paymentID})


	# Check if extra is valid TwitchTurtle
	try:
		extraASCII = binascii.unhexlify(extra.encode()).decode()
		extraDict = ast.literal_eval(extraASCII)
		name = extraDict['name']
		message = extraDict['message'][:255]

		if (len(name) < 2):
			return jsonify({'error': 'Name is too short'}), 400
		if (len(name) > 25) or (len(message) > 255) or (len(extra) > 610):
			return jsonify({'error': 'Name or message is too long'}), 400    # missing arguments
	except Exception as err:
		print(err)
		return jsonify({'error': 'Invalid Arguments'}), 400
	else:
		TipperDB = Tipper(extra = extra)
                # 64 Char paymentID, used for identitfication
		TipperDB.paymentID = '%030x' % random.randrange(16**64) 
		db.session.add(TipperDB)
		db.session.commit()
		return jsonify({'paymentID':TipperDB.paymentID})

@app.route('/api/balance') # Get balance of current logged in user
@auth.login_required
def get_balance():
	user = User.query.filter_by(streamlabs_id=g.user.streamlabs_id).first()
	if not user:
		return jsonify({'error': 'invalid user'}), 400
	if not user.address:
		return jsonify({'error': 'No address'}), 400
	response = walletd.get_balance(user.address)

	return jsonify(response['result'])

@app.route('/api/withdraw/<address>') # Withdraw funds
@auth.login_required
def withdraw_transaction(address):
	# TEMP: Should be sent in POST
	user = User.query.filter_by(streamlabs_id=g.user.streamlabs_id).first()
	if not user:
		return jsonify({'error': 'invalid user'}), 400
	if user.address == address:
		return jsonify({
                        'error': 'Withdraw address cannot be your TwitchTurtle address'
                        }), 400

	# Regex magic, its very fucky-wucky
	regex = r"""
		^TRTL(?:[0-9A-Z]{95}|[0-9A-Z]{183})$
		"""
	matches = re.finditer(regex, address, re.MULTILINE | re.IGNORECASE | re.VERBOSE)
	if not matches:
		return jsonify({'error': 'Invalid address'}), 400
	# End of fucky wucky RegExp

	balance = walletd.get_balance(user.address)['result']['availableBalance']
	if balance > 1001000: # Limit transaction to 100K TRTL, with 10 TRTL as a fee
		balance = 1000000
	elif balance > 10000:
		balance = balance - 130
	elif balance < 10000:
		return jsonify({'error': 'insufficent funds', 'available': balance }), 400

	transfers = [
	    {"address" : address, "amount" : balance},
	]

	print(transfers, address, [user.address])

	try:
		response = walletd.send_transaction(
                    transfers, 
                    3, 
                    10, 
                    [user.address], 
                    '', 
                    '7b226e616d65223a20225769746864726177616c222c226d657373616765223a20225769746864726177616c227d'
                )
	except Exception as e:
		return jsonify({
                    'success' : False, 'error': str(e), 'available': balance 
                }), 400

	return jsonify({
            'success' : True, 
            'sent': balance, 
            'link': response['result']['transactionHash']
        })


@app.route('/api/transactions') # Get transactions of current logged in user
@auth.login_required
def get_transactions():
	# Deprecated, superceeded by userStats 
	user = User.query.filter_by(streamlabs_id=g.user.streamlabs_id).first()
	if not user:
		return jsonify({'error': 'invalid user'}), 400
	if not user.address:
		return jsonify({'error': 'No address'}), 400
	try:
		response = walletd.get_transaction(user.address.split(","))

		return jsonify(response['result']['items'])
	except requests.exceptions.RequestException as e:
		return jsonify({'error': str(e)}), 503
	except ValueError as e:
		if str(e) == "{'code': -32600, 'message': 'Invalid Request'}":
			return jsonify({'error': 'Requested object not found'}), 503
		else:
			return jsonify({'error': str(e)}), 503

@app.route('/api/minAlert', methods=['POST']) # Register a new user
@auth.login_required
def min_Alert():
	minAlertNum = request.json.get('minAlertNum')
	if minAlertNum is None or len(minAlertNum)==0:
		return jsonify({'error': 'Missing arguments'}), 400

	user = User.query.filter_by(streamlabs_id=g.user.streamlabs_id).first()
	if not user:
		return jsonify({'error': 'invalid user'}), 400
	if not user.address:
		return jsonify({'error': 'No address'}), 400
	try:
		user.minAlertNum = minAlertNum
		db.session.commit()
	except requests.exceptions.RequestException as e:
		return jsonify({'error': e}), 503
	except ValueError as e:
		return jsonify({'error': str(e)}), 503
	else:
		return jsonify({'minAlertNum': user.minAlertNum})


@app.route('/api/userStats') # Get transactions of current logged in user
@auth.login_required
def get_user_stats():
	user = User.query.filter_by(streamlabs_id=g.user.streamlabs_id).first()
	if not user:
		return jsonify({'error': 'invalid user'}), 400
	if not user.address:
		return jsonify({'error': 'No address'}), 400
	try:
		response2 = walletd.get_balance(user.address)
		response = walletd.get_transaction(user.address.split(","))

		response3 = walletd.get_status()
		knownBlockCount = response3['result']['knownBlockCount']
		blockCount = response3['result']['blockCount']
	except requests.exceptions.RequestException as e:
		return jsonify({'error': e}), 503
	except ValueError as e:
		if str(e) == "{'code': -32600, 'message': 'Invalid Request'}":
			return jsonify({
                            'balance': response2['result'], 
                            'name': user.username, 'address': user.address
                        })
		else:
			return jsonify({'error': str(e)}), 503
	else:
		return jsonify({
                    'transactions': [x for x in response['result']['items'] if x['transactions']], 
                    'status': {
                        'knownBlockCount': knownBlockCount, 
                        'blockCount': blockCount 
                    }, 
                    'balance': response2['result'], 
                    'name': user.username, 
                    'address': user.address, 
                    'minAlert': user.minAlertNum
                })

if __name__ == '__main__':
	# Create db.sqlite and store the tables there if not already
        if not os.path.exists('db.sqlite'):
		db.create_all()
	
        app.run(debug=settings[env]["debug"])
