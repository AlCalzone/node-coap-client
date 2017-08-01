# node-coap-client
Clientside implementation of the CoAP protocol with DTLS support

## Usage

Request a CoAP resource:
```
const coap = require("node-coap-client").CoapClient;

coap
	.request(
		resource /* string */,
		method /* "get" | "post" | "put" | "delete" */,
		[payload /* Buffer */,]
		[options /* RequestOptions */]
	)
	.then(response => { /* handle response */})
	.catch(err => { /* handle error */ })
	;
```
The resource must be a valid CoAP resource URI, i.e. `coap(s)://hostname:port/path/path/path`.

The RequestOptions object looks as follows, all properties are optional:
```
{
	/** Whether to keep the socket connection alive. Speeds up subsequent requests */
	keepAlive: boolean
	/** Whether we expect a confirmation of the request */
	confirmable: boolean
	/** Whether we want to receive updates */
	observe: boolean
}
```

In order to access secured resources, you must set the security parameters before firing off the request:
```
coap.setSecurityParams(hostname /* string */, params /* SecurityParameters */);
```

The SecurityParameters object looks as follows, for now only PSK key exchanges are supported
```
{
	psk: { 
		"identity": "key"
		// ... potentially more psk identities
	}
}
```

## Changelog

#### 0.0.3 (2015-08-01)
* (AlCalzone) reliability improvements

#### 0.0.2 (2015-07-25)
* (AlCalzone) implemented retransmission of lost messages.

#### 0.0.1
* (AlCalzone) initial release. 


## License
The MIT License (MIT)

Copyright (c) 2017 AlCalzone <d.griesel@gmx.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
