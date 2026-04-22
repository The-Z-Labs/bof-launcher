
print(
"""
             bb                             00000          
zzzzz        bb        eee    aa aa   cccc 00   00 nn nnn  
  zz  _____  bbbbbb  ee   e  aa aaa cc     00   00 nnn  nn 
 zz          bb   bb eeeee  aa  aaa cc     00   00 nn   nn 
zzzzz        bbbbbb   eeeee  aaa aa  ccccc  00000  nn   nn 
                                                           
"""
)

prompt = "[{}] ({}) z-beac0n>"
user = "root"
host = "beast"

while True:
    print(prompt.format(host, user), end='')
    input()
