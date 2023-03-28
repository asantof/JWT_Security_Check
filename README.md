# JWT Security Check

This tool tests a request that implements a JWT token in its Authorization header against a few vulnerabilities:
-  None algorithm vulnerability. Replaces the JWT algorithm with none, None, NONE and/or nOnE. It also removes the signature. It attempts requests with each one of these. 
- Lack of a valid signature: Only removes the signature from the JWT and sends the request.
- Algorithm confusion. You have to provide the public key and in case the JWT uses RS256 as its algorithm then it changes the algorithm and uses that public key to create a new JWT and attempt the request.  NOTE: This test has been commented out until further testing.

Note that the tool works by comparing a valid request (the one you provide) with the requests with the modified JWT token. If both get the same response then it assumes a vulnerability exists. 

Usage:
```
python3 JWT_security_check.py -r <request file> [-p <https|http>] [-k <public key file>]
```

- -r: File containting the request. It must contain the JWT in its Authorization header.
- -p: HTTP or HTTPS. Default is HTTPS.
- -k: Only if the algorithm is RS256. Provide a file with the public key. 
