from wreq import Jar, Cookie
from wreq.blocking import Client
from wreq.emulation import Emulation
from wreq.exceptions import *
from wreq.header import HeaderMap
# TODO add extra functions for interacting with mullvad

class Mullvad:
	def get_relays(self):
		r = self.client.get("https://api.mullvad.net/app/v1/relays")
		r.raise_for_status()
		return r.json()["wireguard"]["relays"]

	def __init__(
		self,
		# token: str = "",
		# token_env: str = "MULLVAD_ACCOUNT_TOKEN",
		# find_token: bool = True
		emulation = Emulation.Firefox147,
		headers: dict = {"Accept": "application/json"},
	):
		self.headers = HeaderMap()

		for k, v in headers.items():
			self.headers[k] = v

		self.client = Client(
			emulation = emulation,
			headers = self.headers
		)
