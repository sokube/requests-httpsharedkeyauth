# requests-httpsharedkeyauth

Python implementation of the client library for https://github.com/blowdart/idunno.Authentication/tree/dev/src/idunno.Authentication.SharedKey 

This is intended to be used as an auth handler for a request object by attaching the proper authorization header. 

# Installation
```
pip install git+https://github.com/sokube/requests-httpsharedkeyauth.git
```

# Usage
```
import requests
from httpsharedkeyauth import HTTPSharedKeyAuth

requests.get(url, auth=HTTPSharedKeyAuth(identifier,key))
```
