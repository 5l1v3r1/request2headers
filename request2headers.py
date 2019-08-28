#### USAGE ###
# Session Handling need to be set to detect when a session dies in Burp (Project options --> Session Handling Rules + Corresponding Macro)
# Macro's need to be setup in burp to detect when the session dies, specifically:
# 1 Session dies, request to login
# 2 After session creds are active, request to CSRF token
# This script will trigger on number two above (after you set the criteria below) and add it to the headers of all new requests
from burp import IBurpExtender, IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
import re
newcsrftoken = []
class BurpExtender(IBurpExtender, IHttpListener):
	def registerExtenderCallbacks(self, callbacks):
		self.helpers = callbacks.getHelpers()
		callbacks.registerHttpListener(self)

	def processHttpMessage(self, toolFlag, messageIsRequest, message):
		#### Set items here #######
		global newcsrftoken # This may need to stay global, I am not good at working with classes
		Unique_CSRF_response_header_string = 'Content-Length: 16'
		CSRF_token_regex = r'^(.{16})$' #this should be something specific just to pull the CSRF key itself from the response
		CSRF_Request_Header = 'X-CSRF-TOKEN: ' #HTTP header containing the CSRF key
		debug = 0 #to turn on debug, change to 1
		burpMessage = 1 # change to zero if you do not want to see what is being changed in the extension output
		###########################
		if not messageIsRequest:
			response = message.getResponse()
			analyzedResponse = self.helpers.analyzeResponse(response)
			body = response[analyzedResponse.getBodyOffset():]
			full = self.helpers.bytesToString(response)
			body_string = body.tostring() #full cleartext response
			comp = re.compile(CSRF_token_regex) # , re.MULTILINE)
			token = comp.findall(body_string)
#			print full.encode('utf-8')
			if debug == 1:
				print "working"
			try:
				if Unique_CSRF_response_header_string in str(full).encode('utf-8', 'ignore'):
					if debug == 1:
						print "working 1"
					if burpMessage == 1:
						print "New CSRF Token Detected:"
					try:
						if debug == 1:
							print "working 2"
						if burpMessage == 1:
							print token[0] + "\n"
					except:
						if debug == 1:
							print "working 3"
						pass
					try:
						if token not in newcsrftoken:
							if debug == 1:
								print "working 4"
							del newcsrftoken[:]
							newcsrftoken.extend(token) #add if not in currentresponse to new header
					except Exception as p:
						if debug == 1:
							print "working 5"
						pass
			except Exception as damn:
				if debug == 1:
					print damn
					return
		if debug == 1:
			print "working 6"
		request = message.getRequest()
		requestInfo = self.helpers.analyzeRequest(request)
		headers = requestInfo.getHeaders()
		newheaders = []
		try:
			test = newcsrftoken[0]
			if debug == 1:
				print "working 7"
		except IndexError:
			return
		for i in range(len(headers)):
			if debug == 1:
				print "working 8"
			if headers[i].startswith(CSRF_Request_Header):
				if str(headers[i].split()[1]) not in newcsrftoken: #may need to single out the response here so its just the token - Split is used to single out the token after the space in the CSRF header: X-CSRF-TOKEN: TOKEN-HERE
					if debug == 1:
						print "working 9"
					if burpMessage == 1:
						print "Old CSRF Headers:"
						print str(headers[i]) + "\n"
					for arg in list(headers):
						if str(headers[i].split()[1]) not in arg:
							if arg not in newheaders:
								newheaders.append(arg)
					newvalue = CSRF_Request_Header + str(newcsrftoken[0])
					if debug == 1:
						print "working 10"
					if newvalue not in newheaders:
						newheaders.append(newvalue)
					bodyr = request[requestInfo.getBodyOffset():]
					if burpMessage == 1:
						print "New Request with updated CSRF:"
						for dd in newheaders:
							print dd
					if debug == 1:
						print "working 11"
					updatedRequest = self.helpers.buildHttpMessage(newheaders, bodyr)
					message.setRequest(updatedRequest)
#			else:
#				return
