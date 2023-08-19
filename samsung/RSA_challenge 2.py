from Crypto.Util.number import bytes_to_long as b2l

pubkeys = dict()

#Alice's RSA public key
pubkeys['Alice'] = {'n': 0xd244a731d125aa8cbbccc5aa44b70686b432589d7a472269059055119e258e471df27d0f08c3c5e109829381754745f47b6bb3a5e3cc5a3b63766aa8c929290596de12234c244d6746398cc81f774441946c6d0444ce23ab146c33876cf84dc122eb0d42c4437e969ad8b72fbc399c82abd2e153e8d27dff56f517c5cb980853, 'e': 79}

#Bob's RSA public key
pubkeys['Bob'] = {'n': 0xd244a731d125aa8cbbccc5aa44b70686b432589d7a472269059055119e258e471df27d0f08c3c5e109829381754745f47b6bb3a5e3cc5a3b63766aa8c929290596de12234c244d6746398cc81f774441946c6d0444ce23ab146c33876cf84dc122eb0d42c4437e969ad8b72fbc399c82abd2e153e8d27dff56f517c5cb980853, 'e': 61}

def send_notices(addr, msg):
	msg = b2l(msg)
	print(msg)
	for recipient, keypair in addr.items():
		#RSA encryption
		ct = pow(msg, keypair['e'], keypair['n'])
		print("{} <- {}".format(recipient, hex(ct)))

send_notices(pubkeys, notice)

'''
$ python3 challenge.py
Alice <- 0x55edc128e01d6a94d92482d4136a60c5db5e295aec9c38e4029649bfc42eb350cf3ccdddc101c5a81d1251f9b061fe55b436eaba101b0238db479e795661ad64dd0e04898bdd637d33b15c155d1141e70efc84923c126f7d93582d5783544780c9a29818a8f47bad2e47967f7609aa3e6caabbd153c77def6d20e7ed4ac267a8
Bob <- 0xcad43d8d2bcb9ab05133e0923896426544fd8a93e80e0b10efc36019b8a7365390b30530f240b25d3affa6ed03983548fe17f085fe3f04a6bd80aa9093eda484e7c9a120e770000570a2044f7aa6ea5dc25ef082c352205f710b07423160b70f100800d3dedf89843a19208054550f22936fe510e7a98fe1c557b7657abfb77b
'''
