# pypace
Implementation of PACE protocol in Python

Needs libs pycryptodome 
  <code>pip install pycryptodomex</code>
  
and pytlv 
  <code>pip install pytlv</code>

In main.py you should set your reader_index(0: first reader, 1: second ...), the password reference (1: MRZ, 2:CAN, 3:PIN, 4: PUK) and the password.
You may need to change the pace_oid and the chat. It depends on what your card supports. See [BSI TR-03110 part 3](https://www.bsi.bund.de/EN/Publications/TechnicalGuidelines/TR03110/BSITR03110.html) for further information
