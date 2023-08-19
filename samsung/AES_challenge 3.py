from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import signal
# from secret import key, flag

def signal_handler(signal_id, stack_frame):
	exit()

signal.signal(signal.SIGALRM, signal_handler)
signal.alarm(3600)
key = b"0"*16
while True:
	try:
		iv = bytes.fromhex(input("IV(hex): "))
		if len(iv) != 16:
			print(len(iv))
			raise Exception
		msg = bytes.fromhex(input("CipherText(hex): "))
		if len(msg) % 16:
			raise Exception
	except:
		print("Wrong input.")
		continue

	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(msg)
	try:
		plaintext = unpad(plaintext, 16)
	except:
		print("Try again.")
		continue

	if plaintext == b"CBC Magic!":
		print(flag)
		break
	else:
		print("Wrong CipherText.")
