def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K


def RC4(data, key):
    key = [ord(c) for c in key]
    S = KSA(key)
    keystream = PRGA(S)
    result = bytes([c ^ next(keystream) for c in data])
    return result


def task1():
    # text, key = open("task1.txt", "r").readlines()
    text = input()
    key = "key"

    encrypted = RC4(text.encode('utf-8'), key)
    print("Зашифрованный текст (в hex):", encrypted.hex())

    decrypted = RC4(encrypted, key)
    print("Расшифрованный текст:", decrypted.decode('utf-8'))