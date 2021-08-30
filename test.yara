rule azorult
{
meta:
description = "2019-03-AZORult"
author = "MT20ACS500"
category = "Lab Practical"

strings:
$a1 = "!This program cannot be run in DOS mode." 	/* exe header */
$c = "http://" wide 					/* check for any http urls*/
$d = "NetUserAdd"					/* func to add a new user*/
$e = "NetLocalGroupAddMembers"				/* func to add a new usergroup*/
$f = "CredEnumerate"					/* enumerates the user creds*/
$h = "CryptUnprotectData"				/* decrypt the creds*/
$i = "LookupAccountSid"					/* security identifier lookup*/
$j = "Reg" wide

condition:
all of ($a*) and 
$c or 
($d and $f) or 
($e and $f) or
($f and $h) or
($j and $i)
}
