from wreq import Jar, Cookie
from wreq.blocking import Client
from wreq.emulation import Emulation
from wreq.exceptions import *
from wreq.header import HeaderMap

class AbuseIPDB:
	def check(self, ip: str) -> int:
		r = self.client.get(f"https://api.abuseipdb.com/api/v2/check", query = {"ipAddress": ip})
		r.raise_for_status()
		return r.json()["data"]["abuseConfidenceScore"]

	# def test(self):
	# 	self.check("1.1.1.1")

	def __del__(self):
		if hasattr(self, "client"):
			self.client.close()

	def __init__(
		self,
		api_key: str,
		emulation = Emulation.Firefox147,
		headers: dict = {"Accept": "application/json"},
	):
		self.headers = HeaderMap()

		for k, v in (headers | {"Key": api_key}).items():
			self.headers[k] = v

		self.client = Client(
			emulation = emulation,
			headers = self.headers
		)

if __name__ == "__main__":
	...
	# import os
	# print(API(os.environ.get("MULLVAD_CHECKER_API_KEY")).test())
	# TODO add argparse here for "check" "validity" "expires" etc etc
