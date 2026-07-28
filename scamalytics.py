from wreq.blocking import Client
from wreq.emulation import Emulation
from wreq import Jar, Cookie
from wreq.header import HeaderMap
from wreq.exceptions import *

class Scamalytics:
	def check(self, ip: str) -> int:
		r = self.client.get(f"https://scamalytics.com/ip/{ip}")
		r.raise_for_status()
		return int(r.text().split("Fraud Score: ")[1].split("</div>")[0])

	# def test(self):
	# 	self.check("1.1.1.1")

	def get_cookies(self):
		""" retrieve final cookies from client """
		for cookie in self.client.cookie_jar.get_all():
			yield {
				"name": cookie.name,
				"value": cookie.value,
				"domain": cookie.domain
			}

	def __del__(self):
		if hasattr(self, "client"):
			self.client.close()

	def __init__(
		self,
		emulation = Emulation.Firefox147,
		headers: dict = {
			"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en",
			"Referer": "https://scamalytics.com/",
			"Connection": "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest": "document",
			"Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-Site": "same-origin",
			"Sec-Fetch-User": "?1",
			"Priority": "u=0, i",
			"TE": "trailers"
		},
		cookies: dict = {}
	):
		self.headers = HeaderMap()

		for k, v in headers.items():
			self.headers[k] = v

		jar = Jar()

		self.og_cookies = cookies

		for cookie in cookies:
			name, value, domain = cookie.values()
			jar.add(Cookie(name = name, value = value), domain)

		self.client = Client(
			emulation = emulation,
			headers = self.headers,
			cookie_store = True,
			cookie_jar = jar
		)

if __name__ == "__main__":
	...
	# import json
	# with open("auth_scamalytics.json", "r") as fp:
	# 	j = json.load(fp)
	# s = Scamalytics(cookies = j["cookies"])
	# s.test()
	# print(list(s.get_cookies()))
