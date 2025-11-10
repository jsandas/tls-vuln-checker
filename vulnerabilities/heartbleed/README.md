Heartbleed is an old vulnerable to specific versions of OpenSSL and anything compiled against those affect versions

The vulnerability is in the heartbeat extension.  The extension allows you to specificy an arbitrary length for the
heartbeat message.  On the server side it does not validate that the message length is correct with the heartbeat 
request length and will cause a buffer overflow and return data in memory to the length of the heartbeat message or
up to 64k.

Go does not support heartbeats and would require forking the tls library to add it.  Instead this check generates the
bytes that make up a tls clientHello and Heartbeat message and send this over a tcp connection while parsing the response
to check if the server returned more data than it should have.  This idea was taken from how the "testssl" package performs 
the heartbleed vulnerability check. (https://github.com/drwetter/testssl.sh/blob/3.0/utils/heartbleed.bash)
