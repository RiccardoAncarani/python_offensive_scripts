import requests
from optparse import OptionParser
import tempfile
import os

class XssFuzzer:
	payloads = [
	"<script>alert(1)</script>",
	"\"><script>alert(1)</script>",
	"\" onerror=\"alert(1)\""
	]

	def getPayloads(self):
		return self.payloads

	def checkResult(self, body, payload):
		if payload in body:
			return True
		else:
			return False

	def makeGoodPostRequest(self,url,data,cookie):
		r = requests.post(url,data=data, cookies=cookie)
		self.good_req = tempfile.NamedTemporaryFile()
		self.good_req.write(r.text)

	def gitDiff(self, text):
		f = tempfile.NamedTemporaryFile()
		f.write(text)
		os.system("git diff --unified=0 " +self.good_req.name + " " + f.name)
		f.close()

	def fuzzPost(self, url, data, cookie):
		for key in data.keys():
			fuzz_dict = {}
			fuzz_dict = data.copy()
			for payload in self.payloads:
				fuzz_dict[key] = payload
				r = requests.post(url, data=fuzz_dict, cookies=cookie)
				self.gitDiff(r.text)
				
				if self.checkResult(r.text, payload):
					print "[!] Found payload: "+ payload + " in body for param: " + key

def main():
	parser = OptionParser(usage="usage: %prog [options] filename",
						  version="%prog 1.0")
	parser.add_option("-u", "--url",
					  action="store",
					  dest="url",
					  default=None,
					  help="Specify the target URL")
	parser.add_option("-d", "--data",
					  action="store", # optional because action defaults to "store"
					  dest="data",
					  default=None,
					  help="The POST data to fuzz",)
	parser.add_option("-c", "--cookie",
					  action="store", # optional because action defaults to "store"
					  dest="cookie",
					  default=None,
					  help="The cookie to send",)
	(options, args) = parser.parse_args()

	if options.url:
		xss = XssFuzzer()
		
		if options.data:
			data = {}

			def splitPost(p):
				d = p.split("=")
				data[d[0]] = d[1]

			post = (options.data).split("&")
			[splitPost(p) for p in post]

		if options.cookie:
			cookie = {}
			def splitCookie(p):
				d = p.split("=")
				cookie[d[0]] = d[1]

			cookies = (options.cookie).split("; ")
			[splitCookie(c) for c in cookies]
		
		if options.data:
			xss.makeGoodPostRequest(options.url, data, cookie)
			xss.fuzzPost(options.url, data, cookie)
		else:
			xss.fuzzGet(options.url,cookie) 
				
	else:
		print "[-] At least we need a URL"

if __name__ == '__main__':
	main()