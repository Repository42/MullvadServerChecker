#!/usr/bin/env python3
import requests, argparse, threading, queue, json, time, datetime

class servers:
	def __scamalytics(self, ip: str) -> int:
		try:
			r = self.session.get('https://scamalytics.com/ip/' + ip)

			if r.status_code == 200:
				return int(r.text.split('<div class="score">Fraud Score: ')[1].split('</div>')[0])
		except:
			pass

	def __threaded(self, inQueue) -> None:
		while not inQueue.empty():
			line = inQueue.get()
			server = line[1]

			if line[0] == 'wireguard':
				if 'daita' in server.keys():
					daita = server['daita']
					server.pop('daita')
				else:
					daita = False

				if 'shadowsocks_extra_addr_in' in server.keys():
					shadowSocksIp = server['shadowsocks_extra_addr_in'][0]
					server['fraud_score_shadowsocks'] = self.__scamalytics(shadowSocksIp)
				else:
					shadowSocksIp = None
					server['fraud_score_shadowsocks'] = None

				server['shadowsocks_extra_addr_in'] = shadowSocksIp
				server['fraud_score_ipv6'] = self.__scamalytics(server['ipv6_addr_in'])
				server['daita'] = daita

			server['fraud_score_ipv4'] = self.__scamalytics(server['ipv4_addr_in'])
			#print(list(server.values()))
			self.output[line[0]].append(server)
			inQueue.task_done()

	def get(self, threadAmount: int = 100, suppress: bool = False) -> list or None: # check mullvad servers against scamalalytics and return as json
		doMessage = lambda message : print(message) if not suppress else ...

		start = time.time()
		servers = self.session.get('https://api.mullvad.net/app/v1/relays').json() #get servers

		self.output = {"wireguard": [], "openvpn": []}

		inQueue = queue.Queue()
		threads = []

		for server in servers['openvpn']['relays']:
			inQueue.put(['openvpn', server])

		for server in servers['wireguard']['relays']:
			inQueue.put(['wireguard', server])

		amount = inQueue.qsize()

		if amount < threadAmount:
			threadAmount = amount

		doMessage(f"Checking {amount} servers.")

		for thread in range(threadAmount):
			t = threading.Thread(target = self.__threaded, args = [inQueue], daemon = True)
			threads.append(t)
			t.start()

		for thread in threads:
			thread.join()

		inQueue.join()

		doMessage(f"Enumerated {len(self.output['wireguard'] + self.output['openvpn'])} servers in: {round((time.time() - start), 2):,} Seconds.")
		return self.output

	def __init__(self, session: requests.Session = requests.Session()):
		self.session = session

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'Check mullvad servers against scamalytics.com to find low fraud score servers')
	parser.add_argument("-s", "--suppress", dest = "suppress", action = "store_true", help = "Suppress output (print messages)")
	parser.add_argument("-f", "--format", dest = "format", action = "store", type = str, nargs = "?", const = "_%d.%m.%Y", default = "_%d.%m.%Y", help = "Filename date format")
	parser.add_argument("-t", '--threads', dest = 'threads', action = 'store', type = int, nargs = '?', const = 100, default = 100, help = "Amount of threads to use")
	args = parser.parse_args()

	servers = servers().get(args.threads, args.suppress)
	date = datetime.datetime.now().strftime(args.format)
	#open("servers.json", "w").write(json.dumps(servers, indent = "\t", ensure_ascii = False))

	if servers["openvpn"] is not None:
		openvpn = open(f'openvpn{date}.csv', 'w')
		openvpn.write('Hostname,Location,Active,Owned,Provider,Stboot,IPV4,IncludeInCountry,Weight,Score\n')
		openvpn.write("\n".join([",".join([str(item) for item in list(server.values())]) for server in servers["openvpn"]]) + "\n")
		openvpn.close()

	if servers["wireguard"] is not None:
		wireguard = open(f'wireguard{date}.csv', 'w')
		wireguard.write('Hostname,Location,Active,Owned,Provider,Stboot,IPV4,IncludeInCountry,Weight,PubKey,IPV6,ShadowSocksAddress,ScoreShadowSocks,ScoreIPV6,Daita,ScoreIPV4\n')
		wireguard.write("\n".join([",".join([str(item) for item in list(server.values())]) for server in servers["wireguard"]]) + "\n")
		wireguard.close()
