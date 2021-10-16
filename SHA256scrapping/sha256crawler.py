from urllib.request import urlopen
import re

#url1 = "https://bazaar.abuse.ch/browse/"
url=input("Enter the url : ")
wp = urlopen(url)
htmlbytes = wp.read()
text = htmlbytes.decode("utf-8")
x = re.findall("[A-Fa-f0-9]{64}", text)
unique_shas = set(x)
print('The SHA256 hashes present in this page are :','\n',unique_shas)



