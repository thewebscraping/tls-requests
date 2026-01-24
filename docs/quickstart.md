# Quickstart Guide for TLS Requests

This guide provides a comprehensive overview of using the `tls_requests` Python library. Follow these examples to integrate the library efficiently into your projects.

* * *

Importing `tls_requests`
------------------------

Begin by importing the library:

```python
import tls_requests
import logging
logging.basicConfig(level=logging.INFO)
```

Making HTTP Requests
--------------------

### GET Request

Fetch a webpage using a GET request:

```python
r = tls_requests.get('https://httpbin.org/get')
r
<Response [200 OK]>
# Cookies now have proper domain backfilled from request URL
```

### POST Request

Make a POST request with data:

```python
r = tls_requests.post('https://httpbin.org/post', data={'key': 'value'})
```

### Other HTTP Methods

Use the same syntax for PUT, DELETE, HEAD, and OPTIONS:

```python
r = tls_requests.put('https://httpbin.org/put', data={'key': 'value'})
r
<Response [200 OK]>
r = tls_requests.delete('https://httpbin.org/delete')
r
<Response [200 OK]>
r = tls_requests.head('https://httpbin.org/get')
<Response [200 OK]>
r
r = tls_requests.options('https://httpbin.org/get')
r
<Response [200 OK]>
```

* * *

Using Client Identifiers
-----------------------

Specify a TLS client profile using the [`client_identifier`](tls/profiles#internal-profiles) parameter:

```python
r = tls_requests.get('https://httpbin.org/get', client_identifier="chrome_120")
```

* * *

HTTP/2 Support
--------------

Enable HTTP/2 with the `http2` parameter:

```python
r = tls_requests.get('https://httpbin.org/get', http2=True, client_identifier="chrome_120")
```

!!! tip
    - **`http2` parameter**:
        - `auto` or `None`: Automatically switch between HTTP/2 and HTTP/1, with HTTP/2 preferred. Used in cases of redirect requests.
        - `http1` or `False`: Force to HTTP/1.
        - `http2`, `True`: Force to HTTP/2.

* * *

URL Parameters
--------------

Pass query parameters using the `params` keyword:

```python
import tls_requests
params = {'key1': 'value1', 'key2': 'value2'}
r = tls_requests.get('https://httpbin.org/get', params=params)
r.url
'<URL: https://httpbin.org/get?key1=value1&key2=value2>'
r.url.url
'https://httpbin.org/get'
r.url.params
<URLParams: dict_items([('key1', 'value1'), ('key2', 'value2')])>
```

Include lists or merge parameters with existing query strings:

```python
params = {'key1': 'value1', 'key2': ['value2', 'value3']}
r = tls_requests.get('https://httpbin.org/get?order_by=asc', params=params)
r.url
'<URL: https://httpbin.org/get?order_by=asc&key1=value1&key2=value2&key2=value3>'
```

* * *

Custom Headers
--------------

Add custom headers to requests:

```python
url = 'https://httpbin.org/headers'
headers = {'user-agent': 'my-app/1.0.0'}
r = tls_requests.get(url, headers=headers)
r.json()
{
  "headers": {
    ...
    "Host": "httpbin.org",
    "User-Agent": "my-app/1.0.0",
    ...
  }
}
```


* * *

Handling Response Content
-------------------------

### Text Content

Decode response content automatically:

```python
r = tls_requests.get('https://httpbin.org/get')
print(r.text)
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Host": "httpbin.org",
    ...
  },
  ...
}
r.encoding
'UTF-8'
```

### Binary Content

Access non-text response content:

```python
r.content
b'{\n  "args": {}, \n  "headers": {\n    "Accept": "*/*", ...'
```

### JSON Content

Parse JSON responses directly:

```python
r.json()
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Host": "httpbin.org",
    ...
  },
  ...
}
```

### Form-Encoded Data

Include form data in POST requests:

```python
data = {'key1': 'value1', 'key2': 'value2'}
r = tls_requests.post("https://httpbin.org/post", data=data)
print(r.text)
{
  "args": {},
  "data": "key1=value1&key1=value2",
  "files": {},
  "form": {},
  ...
}
```

Form encoded data can also include multiple values from a given key.

```python
data = {'key1': ['value1', 'value2']}
r = tls_requests.post("https://httpbin.org/post", data=data)
print(r.text)
{
  ...
  "form": {
    "key1": [
      "value1",
      "value2"
    ]
  },
  ...
}
```

### Multipart File Uploads

Upload files using `files`:

```python
files = {'image': open('static/coingecko.png', 'rb')}
r = tls_requests.post("https://httpbin.org/get", files=files)
print(r.text)
{
  "args": {},
  "data": "",
  "files": {
    "image": "data:image/png;base64, ..."
  },
  ...
}
```

Add custom filenames or MIME types:

```python
files = {'image': ('image.png', open('static/coingecko.png', 'rb'), 'image/*')}
r = tls_requests.post("https://httpbin.org/get", files=files)
print(r.text)
{
  "args": {},
  "data": "",
  "files": {
    "image": "data:image/png;base64, ..."
  },
  ...
}
```

If you need to include non-file data fields in the multipart form, use the `data=...` parameter:

```python
data = {'key1': ['value1', 'value2']}
files = {'image': open('static/coingecko.png', 'rb')}
r = tls_requests.post("https://httpbin.org/get", data=data, files=files)
print(r.text)
{
  "args": {},
  "data": "",
  "files": {
    "image": "data:image/png;base64, ..."
  },
  "form": {
    "key1": [
      "value1",
      "value1"
    ]
  },
  ...
}
```

### JSON Data

Send complex JSON data structures:

```python
data = {
    'integer': 1,
    'boolean': True,
    'list': ['1', '2', '3'],
    'data': {'key': 'value'}
}
r = tls_requests.post("https://httpbin.org/post", json=data)
print(r.text)
{
  ...
  "json": {
    "boolean": true,
    "data": {
      "key": "value"
    },
    "integer": 1,
    "list": [
      "1",
      "2",
      "3"
    ]
  },
  ...
}
```

* * *

Inspecting Responses
--------------------

### Status Codes

Check the HTTP status code:

```python
r = tls_requests.get('https://httpbin.org/get')
r.status_code
200
```

Raise exceptions for non-2xx responses:

```python
not_found = tls_requests.get('https://httpbin.org/status/404')
not_found.status_code
404
not_found.raise_for_status()
```
```text
Traceback (most recent call last):
  ***
  File "<input>", line 1, in <module>
  File "***tls_requests/models/response.py", line 184, in raise_for_status
    raise HTTPError(
tls_requests.exceptions.HTTPError: 404 Client Error: Not Found for url: https://httpbin.org/status/404
```

Any successful response codes will return the `Response` instance rather than raising an exception.

```python
r = tls_requests.get('https://httpbin.org/get')
raw = r.raise_for_status().text
print(raw)
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Host": "httpbin.org",
    ...
  },
  ...
}
```

### Headers

Access headers as a dictionary:

```python
r.headers
<Headers: {
    'access-control-allow-credentials': 'true',
    'access-control-allow-origin': '*',
    'content-length': '316',
    'content-type':
    'application/json',
    'date': 'Wed, 04 Dec 2024 01:31:50 GMT',
    'server': 'gunicorn/19.9.0'
}>
```

The `Headers` data type is case-insensitive, so you can use any capitalization.

```python
r.headers['Content-Type']
'application/json'
```

### Cookies

Access cookies or include them in requests:

```python
url = 'https://httpbin.org/cookies/set?foo=bar'
r = tls_requests.get(url, follow_redirects=True)
r.cookies['foo']
'bar'
```

* * *

Redirection Handling
--------------------

Control redirect behavior using the `follow_redirects` parameter:

```python
redirect_url = 'https://httpbin.org/absolute-redirect/3'
r = tls_requests.get(redirect_url, follow_redirects=False)
r
<Response [302]>
r.history
[]
r.next
<Request: (GET, https://httpbin.org/absolute-redirect/2)>
```

You can modify the default redirection handling with the `follow_redirects` parameter:

```python
redirect_url = 'https://httpbin.org/absolute-redirect/3'
r = tls_requests.get(redirect_url, follow_redirects=True)
r.status_code
200
r.history
[<Response [302]>, <Response [302]>, <Response [302]>]
```

The `history` property of the response can be used to inspect any followed redirects.
It contains a list of any redirect responses that were followed, in the order
in which they were made.

Timeouts
--------

Set custom timeouts:

```python
tls_requests.get('https://github.com/', timeout=10)
```

* * *

Authentication
--------------

Perform Basic Authentication:

```python
r = tls_requests.get("https://httpbin.org/get", auth=("admin", "admin"))
```

* * *

Exceptions
----------

Handle exceptions for network errors or invalid responses:

```python
try:
    r = tls_requests.get('https://httpbin.org/status/404')
    r.raise_for_status()
except tls_requests.exceptions.HTTPError as e:
    print(e)
```
