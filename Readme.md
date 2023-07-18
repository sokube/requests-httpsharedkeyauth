# requests-httpsharedkeyauth
![Workflow](https://github.com/sokube/requests-httpsharedkeyauth/actions/workflows/release.yml/badge.svg)

Python implementation of the client library for the [Shared Key Authentication](https://github.com/blowdart/idunno.Authentication/tree/dev/src/idunno.Authentication.SharedKey).  
This is intended to be used as an authentication handler for a request object by attaching the proper authorization header. 

# Installation

```python
pip install git+https://github.com/sokube/requests-httpsharedkeyauth.git
```

# Usage

```python
import requests
from httpsharedkeyauth import HTTPSharedKeyAuth

requests.get(url, auth=HTTPSharedKeyAuth(identifier,key))
```
