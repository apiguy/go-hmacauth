Go HMACAuth
===========

HMAC Auth for your Go web applications

Quickstart
----------

Go HMACAuth is designed with the Martini web framework in mind, but it
will work perfectly well with a standard `net/http` web application as
well. With that in mind, we'll be using Martini in the examples that
follow.

### Simple Server Example:

```go

package main

import (
	"github.com/apiguy/go-hmacauth"
	"github.com/codegangsta/martini"
)

func main() {
	m := martini.Classic()

	options := hmacauth.Options{
		SignedHeaders:       []string{"Content-MD5", "Content-Type"},
		SecretKey:           hmacauth.KeyLocator(func(apiKey string) string { return "secret" }),
		SignatureExpiresIn: 300 * time.Second,
	}

	m.Use(hmacauth.HMACAuth(options))

	m.Get("/", func() string {
		return "Hello World"
	})

	m.Run()
}

```

Let's take a look at what's happening here. First, you'll notice we're creating
an instance of `hmacauth.Options` which is going to control how `hmacauth`
behaves when a request is received.

Configuration
-------------

There are 3 configurable options you can use to tweak the behavior of
**Go HMACAuth**:

* ### SignedHeaders: `[]string` *Optional*
A string slice of headers that are required to be included when generating the
"string to sign". Regardless of which order you specify the headers in, they
will be sorted before being evaluated.

* ### SecretKey: `func(string) string` *Required*
A function that will return a secret key to use for a given api key. If a value
is not provided, a `panic` will be raised when starting the server.

* ### SignatureExpiresIn: `time.Duration` *Optional*
An duration representing the maximum length of time that a signature is valid
for.

Once you've created an instance of `Options` you can pass it to `HMACAuth` to
get a function with the signature:

```go
func(http.ResponseWriter, *http.Request)
```

...which can then be passed to Martini's `Use` method, or placed in front of any
handler functions in your application.

Writing a Client
----------------

In order for clients to successfully make requests against your application,
they'll need 2 identifying pieces of information from you. First, they'll need
an API Key, and second they'll need a Secret Key which will be used to sign
requests.

Go HMACAuth doesn't care how these values are generated or where they come from,
instead you're allowed the flexibility to define that based on your application
needs. However you get this information to your users, it must be stated that
a user's Secret Key must never be shared and should be kept as private as
possible.

There are 3 steps a client will need to take in order to make successful
requests against your server:

* **Step 1:** Create a "string to sign" based on data in the request and the
current time.

* **Step 2:** Create a signature using HMAC-SHA256, and base64 encode it.

* **Step 3:** Add an `Authorization` header to the request that contains the
APIKey, the Signature, and the Timestamp in RFC3339 format.


### Creating the "string to sign"

This will vary slightly depending on the values you're going to specify in your
`SignedHeaders` options value but typically the process of creating this string
will looks like:

~~~ python
# Python

string_to_sign = \
  METHOD + "\n" +
  HOST + "\n" +
  REQUEST_URI + "\n"
  TIMESTAMP + "\n"

for header in sorted(required_headers):
  string_to_sign += header.value()
  string_to_sign += "\n"

~~~

To elaborate, let's say you've got the following `Options`:

```go
Options{
	SignedHeaders:       []string{"User-Agent", "Content-Type"},
	SecretKey:           KeyLocator(func(apiKey string) string { return "secret" }),
	SignatureExpiration: 300,
}
```

And the client wants to make the following request:

```http
POST /notes/?create=true HTTP/1.1
Host: notes.someapp.com
Content-Type: application/json;charset=UTF-8
User-Agent: CoolClientLib 1.0

{"title": "Go Crazy", "text": "After this week, I'm ready to."}
```

The client will need to construct the "string to sign".

No matter what signed headers you require the first part of the string to sign
is always constructed in the same way:

```
POST
notes.someapp.com
/notes/?create=true
2014-04-01T10:16:38-04:00

```

Next the client will need to add the header values of the headers that you
require. They should be added by order of the name of the Header
(not the value). In this case the required headers are `User-Agent` and
`Content-Type`. When we sort them the `Content-Type` header comes first, so
we add the following to our "string to sign".

```
application/json;charset=UTF-8
CoolClientLib 1.0

```

And we end up with a final "string to sign" that looks like this (don't overlook
the newline character at the end of the string):

```
POST
notes.someapp.com
/notes/?create=true
2014-04-01T10:16:38-04:00
application/json;charset=UTF-8
CoolClientLib 1.0

```

### Signing the String

The client should then sign this string using the Secret Key you provided at
some earlier point in time (For our purposes, we'll pretend the Secret Key is
just the string `"secret"`). Once they have the the signature, it should be
base64 encoded.

~~~ python
# Python

raw_sig = hmac.new("secret", string_to_sign, hashlib.sha256).digest()
encoded_sig = b64encode(raw_sig)

~~~

Which creates the signature:

```
Ii/RLNlJd38suVDA5hRbQqOF7uafallGasC2FIVmhg8=
```

### Creating the Header


With the signature now in hand, we can add the `Authorization` header to our
request. The `Authorization` header should contain a set of parameters, namely
APIKey, Signature, and Timestamp. If we assume the client's APIKey is
`abc123` then the Authorization header should look like:

```
APIKey=abc123,Signature=Ii/RLNlJd38suVDA5hRbQqOF7uafallGasC2FIVmhg8=,Timestamp=2014-04-01T10:16:38-04:00
```

The client can add this to the request, giving us this final result:

```http
POST /notes/?create=true HTTP/1.1
Host: notes.someapp.com
Content-Type: application/json;charset=UTF-8
User-Agent: CoolClientLib 1.0
Authorization: APIKey=abc123,Signature=Ii/RLNlJd38suVDA5hRbQqOF7uafallGasC2FIVmhg8=,Timestamp=2014-04-01T10:16:38-04:00

{"title": "Go Crazy", "text": "After this week, I'm ready to."}
```
