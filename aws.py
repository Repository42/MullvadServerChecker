import ipaddress
from wreq import Jar, Cookie
from wreq.blocking import Client
from wreq.emulation import Emulation
from wreq.exceptions import *
from wreq.header import HeaderMap

class AWS:
	def check(self, ip: str) -> bool:
		ip = ipaddress.ip_address(ip)

		for prefix in self.ranges["prefixes"]:
			if ip.version == 4 and ip in ipaddress.ip_network(prefix["ip_prefix"]):
				return prefix

		for prefix in self.ranges["ipv6_prefixes"]:
			if ip.version == 6 and ip in ipaddress.ip_network(prefix["ipv6_prefix"]):
				return prefix

		return False

	def __init__(
		self,
		emulation = Emulation.Firefox147,
		headers: dict = {},
	):
		self.headers = HeaderMap()

		for k, v in headers.items():
			self.headers[k] = v

		self.client = Client(
			emulation = emulation,
			headers = self.headers
		)
		r = self.client.get("https://ip-ranges.amazonaws.com/ip-ranges.json")
		r.raise_for_status()
		self.ranges = r.json()
