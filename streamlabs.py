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
import subprocess
import threading
import string
import requests
from datetime import datetime
import calendar
from walletd import Walletd
import random
import decimal
import binascii
import json
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
import sys
from sqlalchemy_utils import UUIDType
import uuid
import ast
import re

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
db = SQLAlchemy(app)

rpc_password = settings[env]["turtle-service"]["rpc_password"]
rpc_host = settings[env]["turtle-service"]["rpc_host"]
rpc_port = settings[env]["turtle-service"]["rpc_port"]

client_id =  settings[env]["streamLabs"]["client_id"]
client_secret = settings[env]["streamLabs"]["client_secret"]
redirect_uri = settings[env]["streamLabs"]["redirect_uri"]


walletd = Walletd(rpc_password, rpc_host, rpc_port)


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

'''
START STREAMLABS CODE
'''
class Stream:
	def getRefreshToken(code):
	        # take authorization code from Streamlabs and pipe it to streamlabs to  
                # recieve access_token and refresh_token
		url = "https://streamlabs.com/api/v1.0/token"

		querystring = {
			'grant_type': "authorization_code",
			'client_id': client_id,
			'client_secret': client_secret,
			'redirect_uri': redirect_uri,
			'code': code
		}
		response = requests.request("POST", url, data=querystring)
		d = datetime.utcnow()
		unixtime = calendar.timegm(d.utctimetuple())

		streamKeys = [
                        response.json().get('access_token'), 
                        response.json().get('refresh_token'), (unixtime + 3600)
                ]
		return streamKeys

	def getNewTokens(refresh_token):
        	# Take authorization code from Streamlabs and pipe to streamlabs to 
                # get the access_token and refresh_token
		url = "https://streamlabs.com/api/v1.0/token"

		querystring = {
			'grant_type': "refresh_token",
			'client_id': client_id,
			'client_secret': client_secret,
			'redirect_uri': redirect_uri,
			'refresh_token': refresh_token
		}
		response = requests.request("POST", url, data=querystring)
		d = datetime.utcnow()
		unixtime = calendar.timegm(d.utctimetuple())

		streamKeys = [
                        response.json().get('access_token'), 
                        response.json().get('refresh_token'), 
                        (unixtime + 3600)
                ]

		return streamKeys

	def postTransaction(amount, trtl, extra, access_token, refresh_token):
		# Convert The extra data and send it to streamlabs.py
		extra = '7b226e' + extra.split('7b226e', 1)[-1]

		try:
			extraASCII = binascii.unhexlify(extra.encode()).decode()
			extraDict = ast.literal_eval(extraASCII)
			name = extraDict['name']
			message = extraDict['message'][:255]

			if (len(name) < 2) or (len(name) > 25):
				name = "Name is Invalid"
		except Exception as err:
			print(err, extra)
			Stream.postDonation(
                                settings[env]["default-name"], 
                                settings[env]["default-message"], 
                                amount, 
                                trtl, 
                                'USD', 
                                access_token, 
                                refresh_token
                        )
		else:
			Stream.postDonation(
                                name, 
                                message, 
                                amount, 
                                trtl, 
                                'USD', 
                                access_token, 
                                refresh_token
                        )

	def searchForTransaction(lastBlockCount=None): 
                # Search TRTL network for incoming donations
		responseStatus = walletd.get_status()
                # Get local node height
		blockCount = responseStatus['result']['blockCount'] 
		# Get network height
                knownBlockCount = responseStatus['result']['knownBlockCount'] 
                # If lastBlockCount is not set, that means program has just been 
                # restarted, go two blocks back
		if not lastBlockCount: 
			lastBlockCount = blockCount  - 2
		threading.Timer(
                        2, 
                        Stream.searchForTransaction, args=[blockCount],
                ).start() # Restart async call 
                # If the local blockchain didn't sync the block in time and there 
                # is a new block, account for that
		if ((blockCount - lastBlockCount) > 1): 
                        # Set skipped block detector to the blockCount 
                        # minus the amount of skipped blocks
			skippedBlockDetector = blockCount - (blockCount-lastBlockCount)
		elif ((blockCount - lastBlockCount) == 1):
			skippedBlockDetector = blockCount - 1
		else:
			skippedBlockDetector = blockCount

		if (blockCount > lastBlockCount): 
                        # If the network found a new block, check the transactions 
			print(f"New block detected! Checking block {blockCount}, last block was {lastBlockCount}")
			try:
				try:
					response = walletd.get_transactions(
                                                        skippedBlockDetector, 
                                                        1
                                                    ) 
                                        # Get transactions from the last block, 
                                        # or more if the skippedBlockDetector requires
					responseItems = response['result']['items']
				except ValueError as e:
					print(f"Requested start block {skippedBlockDetector}. ",
                                              f"Top network block {blockCount} last blockcount {lastBlockCount}")
					return
				for x in responseItems:
					for y in x['transactions']: 
                                                # New transaction detected
						Stream.donationReceived(y)

			except Exception as err:
				print(err)
				return

	def donationReceived(transaction):
		# First search for the paymentID in the db to see if a user has set 
                # their message there
		TipperDB = Tipper.query.filter_by(
                        paymentID=transaction['paymentId']
                ).first()
		if TipperDB is not None: 
                        # Payment ID is in the tipper db, get extra from the db
			extra = TipperDB.extra
			print('Came from DB')
		else: 
                        # Payment ID does not exist, pass tx_extra to be parsed and read
			extra = transaction['extra']
			print('Actual extra')
		
                dbUser = User.query.filter_by(
                        address=transaction['transfers'][0]['address']
                ).first()
		print(f"Incoming tip! {transaction['amount']} for user {dbUser.username} inside block {transaction['blockIndex']}")
		trtl = transaction['amount'] / 100
		coinmarketcap = "https://api.coinmarketcap.com/v2/ticker/" + settings[env]["coinmarketcapTicker"] + "/?convert=USD"
		r = requests.request("GET", coinmarketcap)
		convertTRTL = r.json().get('data').get('quotes').get('USD').get('price')
		amount = trtl * convertTRTL
		if(dbUser.minAlertNum < amount):
			Stream.postTransaction(
                                amount, 
                                trtl, 
                                extra, 
                                dbUser.access_token, 
                                dbUser.refresh_token
                        )
		else:
			print('Too low')
	def postDonation(
                name, message, amount, trtl, currency, access_token, refresh_token
        ):

			message = f"{message} ({str(trtl)} {settings[env]['coinName']})"


			url = "https://streamlabs.com/api/v1.0/donations"

			querystring = {
				'name': name,
				'message': message,
				'identifier': name,
				'amount': amount,
				'currency': currency,
				'access_token': access_token,
			}
			response = requests.request("POST", url, data=querystring)
			if response.status_code != 200:
                                # Request failed, refresh tokens and retry
				user = User.query.filter_by(
                                        access_token=access_token
                                ).first()

				keys = Stream.getNewTokens(refresh_token)

				user.refresh_token = keys[1]
				user.access_token =  keys[0]
				user.expires_on = keys[2]

				querystring = {
					'name': name,
					'message': message,
					'identifier': name,
					'amount': amount,
					'currency': currency,
					'access_token': user.access_token,
				}

				db.session.commit()

				response = requests.request(
                                        "POST", url, data=querystring
                                )
				print(response.text)


			print(response.text)
