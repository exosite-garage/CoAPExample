This is a demo for using the Exosite CoAP API.

Full documentation for the CoAP API can be found at 
https://github.com/exosite/docs/tree/master/coap

Note: The CoAP API is in beta. It will change before it is released, this
example may be out of date.

# Known Issues
`humanFormatMessage()` will always say that outgoing messages are improperly
formatted.

This is a very simple example which does not exactly follow the CoAP protocol. It is only for testing and demonstration purposes. It does not even impliment basic features like retrying on lost packets. For a more complete library see https://github.com/siskin/txThings (not affiliated with Exosite).
