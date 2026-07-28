#!/usr/bin/env python3
import argparse
import datetime
import json
import os
import queue
import threading
import time
from mullvad import Mullvad
from aws import AWS
from abuseipdb import AbuseIPDB
from scamalytics import Scamalytics

class colours:
	red = "\x1b[38;2;255;0;0m"
	green = "\x1b[38;2;0;255;0m"
	blue = "\x1b[38;2;0;0;255m"
	pink = "\x1b[38;2;255;0;255m"
	end = "\x1b[0m"

class DryRun:
	def check(self, ip):
		# time.sleep(int.from_bytes(os.urandom(1)) / 3000)
		time.sleep(0.002)
		return int.from_bytes(os.urandom(1)) % 100

	def test(self):
		return self.check("lalallala")

	def __init__(self, random_delay = 3000):
		...

class Program:
	def gui(self):
		# info = f"{colours.pink}[Args]{colours.end} " + \
		# " | ".join([f"{key}: {colours.pink}{value}{colours.end}" for key, value in vars(self.args).items()])

		while self.running: #self.in_queue.empty():
			elapsed = round(time.time() - self.stats["start"], 2)
			rps = round(max(1, self.stats["count"]) / elapsed)
			message = (
				f"\n"
				f"==={colours.pink}mullvad checker{colours.end}===\n"
				f"Count/Amount: {colours.pink}{self.stats["count"]:,}{colours.end}/{colours.pink}{self.stats["amount"]:,}{colours.end}\n"
				f"  Hits/Fails: {colours.green}{self.stats['hits']:,}{colours.end}/{colours.red}{self.stats['fails']:,}{colours.end}\n"
				f"     Elapsed: {colours.pink}{round(elapsed):,}{colours.end}\n"
				f"   Remaining: {colours.pink}{round((self.stats['amount'] - max(1, self.stats['count'])) / rps)}{colours.end}\n"
				f"     RPS/CPM: {colours.pink}{rps:,}{colours.end} / {colours.pink}{rps * 60:,}{colours.end}"
			)
			print(message)
			time.sleep(self.args.delay)
			print("\x1b[1A\x1b[2K" * (message.count("\n") + 1), end = "")
		print(message + "\n")

	def extras(self, ip):
		if self.args.extras:
			return self.check(ip)

	def check(self, ip):
		try:
			score = self.api.check(ip)
			self.stats["hits"] += 1
			return score
		except:
			self.stats["fails"] += 1

	def threaded(self) -> None:
		while not self.in_queue.empty():
			server = self.in_queue.get()
			keys = server.keys()

# Hostname,Location,Active,Owned,Provider,Stboot,IPV4,IPv4InAws,IPV4Score,IncludeInCountry,Weight,PubKey,IPV6,IPV6InAws,IPV6Score,ShadowSocksAddress,ShadowSocksInAws,ShadowSocksScore,Daita
			new_server = {
				"hostname": server["hostname"],
				"location": server["location"],
				"active": server["active"],
				"owned": server["owned"],
				"provider": server["provider"],
				"stboot": server["stboot"],
				"ipv4_addr_in": server["ipv4_addr_in"],
				"ipv4_in_aws": self.aws.check(server["ipv4_addr_in"]),
				"ipv4_score": self.check(server["ipv4_addr_in"]),
				"include_in_country": server["include_in_country"],
				"weight": server["weight"],
				"pubkey": server["public_key"],
				"ipv6_addr_in": server["ipv6_addr_in"],
				"ipv6_in_aws": self.aws.check(server["ipv6_addr_in"]),
				"ipv6_score": self.extras(server["ipv6_addr_in"]),
				"shadowsocks_addr_in": server["shadowsocks_extra_addr_in"][0] if "shadowsocks_extra_addr_in" in keys else None,
				"shadowsocks_in_aws": self.aws.check(server["shadowsocks_extra_addr_in"][0]) if "shadowsocks_extra_addr_in" in keys else None,
				"shadowsocks_score": self.extras(server["shadowsocks_extra_addr_in"][0]) if "shadowsocks_extra_addr_in" in keys else None,
				"daita": True if "daita" in keys else False,
				"quic_addr_in": None,
				"quic_in_aws": None,
				"quic_score": None
			}

			if "features" in keys:
				if "quic" in server["features"].keys():
					new_server.update({
						"quic_addr_in": server["features"]["quic"]["addr_in"][0],
						"quic_in_aws": self.aws.check(server["features"]["quic"]["addr_in"][0]),
						"quic_score": self.extras(server["features"]["quic"]["addr_in"][0])
					})

			self.out_queue.put(new_server)
			self.in_queue.task_done()
			self.stats["count"] += (4 if self.args.extras else 1)

	def __init__(self):
		parser = argparse.ArgumentParser(description = "Check mullvad servers to find low fraud score servers.")
		parser.add_argument("--delay", action = "store", type = float, default = 0.5, help = "Delay between `GUI` thread updates.")
		parser.add_argument("--threads", dest = "threads", action = "store", type = int, nargs = "?", const = 100, default = 100, help = "Max amount of threads to use.")
		parser.add_argument("-c", "--auth", dest = "auth", action = "store", type = str, default = "$MULLVAD_CHECKER_AUTH", help = "Authentication file location.")
		parser.add_argument("-g", "--gui", dest = "gui", action = "store_false", help = "Disable gui.")
		parser.add_argument("-f", "--format", dest = "format", action = "store", type = str, nargs = "?", const = "%d.%m.%Y", default = "%d.%m.%Y", help = "Filename date format.")
		parser.add_argument("-t", "--type", dest = "filetype", action = "store", type = str, nargs = "?", choices = ["tsv", "json"], const = "tsv", default = "tsv", help = "File type, either json or tsv.")
		parser.add_argument("-a", "--api", dest = "api", action = "store", type = str, choices = ["abuseipdb", "scamalytics", "dryrun"], default = "scamalytics", help = "API to use for checks.")
		parser.add_argument("-e", "--extra", dest = "extras", action = "store_true", help = "Check other ips assosciated with server such as shadow socks and ipv6 (will use more api credits).")
		self.args = parser.parse_args()

		if not self.args.auth:
			raise ValueError("You need to set MULLVAD_CHECKER_AUTH in your .bashrc")

		auth_path = os.path.expanduser(os.path.expandvars(self.args.auth))

		if not os.path.exists(auth_path):
			print(f"[{colours.red}!{colours.end}] Could not locate authentication @ `{colours.pink}{auth_path}{colours.end}`")
			exit()

		with open(auth_path) as fp:
			authentication = json.load(fp)

		print(f"[{colours.green}+{colours.end}] Loaded authentication from file @ `{colours.pink}{auth_path}{colours.end}`")
		print(f"[{colours.pink}~{colours.end}] Using {'cookie' if 'cookies' in authentication.keys() else 'api_key'} authentication.")

		match self.args.api:
			case "abuseipdb":
				self.api = AbuseIPDB(api_key = authentication["key"])
			case "scamalytics":
				self.api = Scamalytics(cookies = authentication["cookies"])
			case "dryrun":
				self.api = DryRun()
			case _:
				print(f"[{colours.red}!{colours.end}] You supplied an invalid API: `{colours.pink}{self.args.api}{colours.end}`")
				exit()

		print(f"[{colours.pink}~{colours.end}] Using {self.args.api} api.")
		print(f"[{colours.pink}~{colours.end}] Checking api...")

		try:
			self.api.check("1.1.1.1")
			print(f"[{colours.green}+{colours.end}] Api check succeeded!")
		except:
			print(f"[{colours.red}!{colours.end}] Your authentication is invalid or you are being ratelimited by the api!")
			exit()

		print(f"[{colours.pink}~{colours.end}] Getting mullvad servers.")
		mullvad = Mullvad()
		servers = mullvad.get_relays()

		self.in_queue = queue.Queue()
		self.out_queue = queue.Queue()

		for server in servers:
			self.in_queue.put(server)

		print(f"[{colours.pink}~{colours.end}] Getting aws ip ranges.")
		self.aws = AWS()

		self.stats = {
			"start": time.time(),
			"amount": self.in_queue.qsize() * (4 if self.args.extras else 1),
			"count": 0,
			"hits": 0,
			"fails": 0
		}

		# input(self.aws(self.in_queue.get()[1]["ipv4_addr_in"]))
		print(f"[{colours.pink}~{colours.end}] Checking {self.stats['amount']:,} servers.")

		if (threadAmount := min(self.stats["amount"], self.args.threads)) < 1:
			print(f"[{colours.red}!{colours.end}] Program requires atleast one thread!")

		threads = []

		try:
			for thread in range(threadAmount):
				thread = threading.Thread(target = self.threaded, daemon = True)
				threads.append(thread)
				thread.start()

			self.running = True

			if self.args.gui:
				gui = threading.Thread(target = self.gui)
				gui.start()

			for thread in threads:
				thread.join()

			self.in_queue.join()
			self.running = False

			if self.args.gui:
				gui.join()
		except KeyboardInterrupt:
			print(f"[{colours.red}!{colours.end}] Program exitted prematurely!")
			exit()

		print(f"[{colours.green}+{colours.end}] Enumerated {self.out_queue.qsize()} servers in: {round(time.time() - self.stats['start']):,} Seconds.")
		output = []

		while not self.out_queue.empty():
			output.append(self.out_queue.get())

		date = datetime.datetime.now().strftime(self.args.format)

		with open(path := f"servers_{date}.{self.args.filetype}", "w") as fp:
			if self.args.filetype == "tsv":
				fp.write("\t".join(list(output[0].keys())) + "\n")
				fp.write(
					"\n".join([
						"\t".join([
							str(item) for item in list(server.values())
						]) for server in output
					]) + "\n"
				)
			else:
				json.dump(output, fp, ensure_ascii = False, indent = "\t")

		# TODO save cookies back to file after finished except it doesnt really matter and idc either
		# maybe do some shit to get cookies from browser? idk idc
		# # save cookies
		# if authentication["type"] == "cookies":
		print(f"[{colours.green}+{colours.end}] Saved servers to `{path}`")

if __name__ == "__main__":
	Program()
