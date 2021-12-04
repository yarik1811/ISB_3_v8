import json  # для хранения настроек
import argparse  # дабы работало с командной строки
import os  # проверка наличия файлов и генерация ключей
import wget  # для загрузки исходного текста, если он отсутствует
from prettytable import PrettyTable  # чисто для красоты вывода :)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

settings = {
	'initial_file': 'file.txt',  # путь к исходному файлу
	'encrypted_file': 'encrypted_file.txt',  # путь к зашифрованному файлу
	'decrypted_file': 'decrypted_file.txt',  # путь к расшифрованному файлу
	'symmetric_key': 'symmetric_key.txt',  # путь к симметричному ключу
	'public_key': 'public_key.pem',  # путь к открытому ключу
	'secret_key': 'secret_key.pem',  # путь к закрытому ключу
	'vec_init': 'iv.txt'
}

# gen  = Запускает режим генерации ключей
# enc  = Запускает режим шифрования
# dec  = Запускает режим дешифрования
parser = argparse.ArgumentParser()
parser.add_argument('mode', help='Режим работы')
args = parser.parse_args()


def generation(symmetric_k, public_k, secret_k):
	print('Длина ключа от 32 до 448 бит с шагом 8 бит')
	key_len = int(input('Введите желаемую длину ключа: '))

	while True:
		# проверка правильности введенной желаемой длины ключа
		if key_len % 8 != 0 or key_len < 32 or key_len > 448:
			key_len = int(input('Введите желаемую длину ключа: '))
		else:
			break
	key = os.urandom(key_len)  # генерация ключа с длиной key_len
	with open(symmetric_k, 'wb') as key_file:
		key_file.write(key)

	# генерация пары ключей для асимметричного алгоритма шифрования
	keys = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048
	)
	secret_key = keys
	public_key = keys.public_key()

	# сериализация открытого ключа в файл
	with open(public_k, 'wb') as public_out:
		public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
												 format=serialization.PublicFormat.SubjectPublicKeyInfo))
	# сериализация закрытого ключа в файл
	with open(secret_k, 'wb') as secret_out:
		secret_out.write(secret_key.private_bytes(encoding=serialization.Encoding.PEM,
													format=serialization.PrivateFormat.TraditionalOpenSSL,
													encryption_algorithm=serialization.NoEncryption()))

	# открываем файл с симметричным ключом
	with open(symmetric_k, 'rb') as key_file:
		key = key_file  # забираем его содержимое в переменную key
	text = bytes(str(key), 'UTF-8')
	c_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

	# перезаписываем в файл с симметричным ключом зашифрованный симметричный ключ
	with open(symmetric_k, 'wb') as key_file:
		key_file.write(c_text)

	print(f'Ключи асимметричного шифрования сериализованы по адресу: {public_k}\t{secret_k}')
	print(f"Ключ симметричного шифрования:\t{symmetric_k}")
	pass


def print_info(text):
	print('\n')
	table = PrettyTable()
	table.field_names = ['Info']
	table.add_row([text])
	print(table)
	print('\n')
	pass


def encrypting(inital_f, secret_k, symmetric_k, encrypted_f, vec_init):
	with open(secret_k, 'rb') as pem_in:
		private_bytes = pem_in.read()
	private_key = load_pem_private_key(private_bytes, password=None, )
	with open(symmetric_k, 'rb') as key:
		symmetric_bytes = key.read()
	from cryptography.hazmat.primitives.asymmetric import padding
	d_key = private_key.decrypt(symmetric_bytes,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))
	print(f'Key: {d_key}')

	with open(inital_f, 'rb') as o_text:
		text = o_text.read()
	from cryptography.hazmat.primitives import padding
	pad = padding.ANSIX923(64).padder()
	padded_text = pad.update(text) + pad.finalize()
	# случайное значение для инициализации блочного режима, должно быть размером с блок и каждый раз новым
	iv = os.urandom(8)
	with open(vec_init, 'wb') as iv_file:
		iv_file.write(iv)
	cipher = Cipher(algorithms.Blowfish(d_key), modes.CBC(iv))
	encryptor = cipher.encryptor()
	c_text = encryptor.update(padded_text) + encryptor.finalize()
	with open(encrypted_f, 'wb') as encrypt_file:
		encrypt_file.write(c_text)
	print(f"Текст зашифрован и сериализован по адресу: {encrypted_f}")
	pass


def decrypting(encrypted_f, secret_k, symmetric_k, decrypted_file, vec_init):
	with open(secret_k, 'rb') as pem_in:
		private_bytes = pem_in.read()
	private_key = load_pem_private_key(private_bytes, password=None, )
	with open(symmetric_k, 'rb') as key:
		symmetric_bytes = key.read()
	from cryptography.hazmat.primitives.asymmetric import padding
	d_key = private_key.decrypt(symmetric_bytes,
								padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
											 label=None))
	with open(encrypted_f, 'rb') as e_text:
		text = e_text.read()
	# дешифрование и депаддинг текста симметричным алгоритмом
	with open(vec_init, 'rb') as iv_file:
		iv = iv_file.read()
	cipher = Cipher(algorithms.Blowfish(d_key), modes.CBC(iv))
	decrypter = cipher.decryptor()
	from cryptography.hazmat.primitives import padding
	unpadded = padding.ANSIX923(64).unpadder()
	d_text = unpadded.update(decrypter.update(text) + decrypter.finalize()) + unpadded.finalize()
	print("Расшифрованный текст:")
	print(d_text.decode('UTF-8'))
	with open(decrypted_file, 'w', encoding='UTF-8') as decrypt_file:
		decrypt_file.write(d_text.decode('UTF-8'))
	print(f"Текст расшифрован и сериализован по адресу:  {decrypted_file} ")
	pass


def main():
	while True:
		if args.mode == 'gen':
			print_info('Запущен режим создания ключей')
			if not os.path.exists('settings.json'):
				with open('settings.json', 'w') as fp:
					json.dump(settings, fp)
			with open('settings.json', 'r') as json_file:
				settings_data = json.load(json_file)
			generation(settings_data['symmetric_key'], settings_data['public_key'], settings_data['secret_key'])
			break
		elif args.mode == 'enc':
			print_info('Запущен режим шифрования')
			if not os.path.exists('settings.json'):
				with open('settings.json', 'w') as fp:
					json.dump(settings, fp)
			with open('settings.json', 'r') as json_file:
				settings_data = json.load(json_file)
			if not os.path.exists('file.txt'):
				print('Отсутствует файл с исходным текстом, ща скачаю :)')
				url = 'https://github.com/yarik1811/ISB_3_v8/raw/main/file.txt'
				wget.download(url, os.getcwd())
				print('\n')
			if not os.path.exists(settings_data['secret_key']):
				print('Не найден закрытый ключ. Используйте сначала режим gen')
				break
			if not os.path.exists(settings_data['symmetric_key']):
				print('Не найден симметричный ключ. Используйте сначала режим gen')
				break
			encrypting(settings_data['initial_file'], settings_data['secret_key'],
					   settings_data['symmetric_key'], settings_data['encrypted_file'], settings_data['vec_init'])
			break
		elif args.mode == 'dec':
			print_info('Запущен режим дешифрования')
			if not os.path.exists('settings.json'):
				with open('settings.json', 'w') as fp:
					json.dump(settings, fp)
			with open('settings.json', 'r') as json_file:
				settings_data = json.load(json_file)
			if not os.path.exists('file.txt'):
				print('Отсутствует файл с исходным текстом, ща скачаю :)')
				url = 'https://github.com/yarik1811/ISB_3_v8/raw/main/file.txt'
				wget.download(url, os.getcwd())
				print('\n')
			if not os.path.exists(settings_data['secret_key']):
				print('Не найден закрытый ключ. Используйте сначала режим gen')
				break
			if not os.path.exists(settings_data['symmetric_key']):
				print('Не найден симметричный ключ. Используйте сначала режим gen')
				break
			if not os.path.exists(settings_data['encrypted_file']):
				print('Не найден зашифрованный файл. Используйте сначала режим enc')
				break
			decrypting(settings_data['encrypted_file'], settings_data['secret_key'],
					   settings_data['symmetric_key'], settings_data['decrypted_file'], settings_data['vec_init'])
			break
		else:
			print('Нет такого режима работы с файлом, проверьте и перезапустите o_O')
			break
	pass


if __name__ == '__main__':
	main()
