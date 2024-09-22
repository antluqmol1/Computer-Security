# HOW TO EXECUTE THE CODE

## First, We have to run the ftserv:

1. We open a terminal, inside the project We do: cd src
2. After, We do: python ftserv.py --file ../messages/plaintext.txt
   We can change the plaintext.txt among all the ones that are in the folder messages.
   We can also specify the port (12345 as default) in the arguments doing:
   python ftserv.py --file ../messages/plaintext.txt --port 8080 (8080 as an example)

### Now, the RSA keys have been generated and the server is listening on the port specified

## After, We have to run the ftclient:

1. We open a new terminal, inside the project We do: cd src
2. After, We do: python ftclient.py --dest ../generated/received_file.txt
   We can change the name of the received_file as We want
   We can also specify the port and the host with the parameters --port and --host, that are 12345 and 'localhost' as default

## Also, For running tests.py, where We have an integrity check, the only thing We have to do is:

1. We open a new terminal, inside the project We do: cd src
2. After, We do: python tests.py
