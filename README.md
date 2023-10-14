# requests-scram

Implements RFC 7804 Salted Challenge Response (SCRAM) HTTP Authentication Mechanism for the
[Requests](https://requests.readthedocs.io/) library.

See [flask-scram](https://github.com/COUR4G3/flask-scram) for a server-side implementation.

Took much inspiration from [requests-ntlm2](https://github.com/dopstar/requests-ntlm2) and
[requests-gssapi](https://github.com/pythongssapi/requests-gssapi/).


## Getting Started

Initialize ``HTTPSCRAMAuth`` and pass as the ``auth`` parameter to your request or session:

```python
import requests

from requests_scram import HTTPSCRAMAuth

# specify ``mechanisms`` for supported mechanisms (defaults to all non-PLUS)
auth = HTTPSCRAMAuth("user", "pass")

resp = requests.get("http://localhost:5000", auth=auth)
resp.raise_for_status()

print(resp.text)

```


## Todo

- Handle multiple ``WWW-Authenticate`` headers (server would typically advertise multiple SCRAM authentication mechanisms)
- Do something with ``Authentication-Info``?
- Implement [One Round-Trip Reauthentication](https://datatracker.ietf.org/doc/html/rfc7804#section-5.1)


## License

Licensed under the MIT License.
