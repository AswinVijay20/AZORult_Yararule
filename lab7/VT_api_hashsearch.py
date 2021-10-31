#import sys
import requests
#import hashlib
import json
import csv
import time

file = "mdf_files.txt"
url = "https://www.virustotal.com/vtapi/v2/file/report"
list1 = []
with open(file, 'rb') as afile:
	Lines = afile.readlines()
	for line in Lines:
		line = line.rstrip()
		parameters = {'apikey': "8c61b4d3808569cf184d65d8e2b380e5ea87821208e575724cd29b15e9e9dffa", 'resource': line}

		response = (requests.get(url, params=parameters)).json()
		#print(response)

		if response['response_code'] == 0:
			print(response['verbose_msg'])
			msg = response['resource'] + " -----> " +response['verbose_msg']
			rows = [msg]
			list1.append(rows)
		elif response['response_code'] == 1:
			print(response['scans'])
			print("Detected: " + str(response['positives']) + "/" + str(response['total']))
			scan_id = response['scan_id']
			scan_date = response['scan_date']
			sha256 = response['sha256']
			sha1 = response['sha1']
			md5 = response['md5']
			positives = response['positives']
			total = response['total']
			permalink = response['permalink']
			# all_details = [sha256, sha1, md5, positives, total]
			rows = [scan_id, scan_date, sha256, sha1, md5, positives, total, permalink]
			list1.append(rows)
		else:
			print("Something went wrong.")
	afile.close()

fieldnames = ['scan_id', 'scan_date','sha256', 'sha1', 'md5', 'positives', 'total', 'permalink']
with open("data.csv", "wt", newline='', encoding='utf-8') as file:
	writer = csv.writer(file, delimiter=',')
	writer.writerow(fieldnames)
	writer.writerows(list1)
	file.close()


exitmsg = input("Press any key to exit!")