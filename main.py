from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Генерация ключей для пользователя и другой стороны
print("Генерация ключей для пользователя и другой стороны...")
user_private_key, user_public_key = generate_keys()
other_private_key, other_public_key = generate_keys()

print("\nКлючи пользователя:")
print(f"Приватный ключ пользователя: {user_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).hex()}")
print(f"Открытый ключ пользователя: {user_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")

print("\nКлючи другой стороны:")
print(f"Приватный ключ другой стороны: {other_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).hex()}")
print(f"Открытый ключ другой стороны: {other_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")

# Получение сообщения от пользователя
message = input("\nВведите сообщение для подписи: ").encode()

# Подписание сообщения пользователем
print("\nПодписание сообщения пользователем...")
user_signature = sign_data(user_private_key, message)

print("\nПроверка подписи другой стороной...")

# Проверка подписи другой стороной
is_verified = verify_signature(user_public_key, message, user_signature)
if is_verified:
    print("\nПодпись верна: сообщение подлинное")
else:
    print("\nПодпись не верна: сообщение изменено или поддельное")

# Симуляция подделанной подписи для демонстрации
fake_signature = b"fake_signature"  # Заглушка для подделанной подписи

print("\nСимуляция подделанной подписи...")
is_verified_fake = verify_signature(user_public_key, message, fake_signature)
if is_verified_fake:
    print("Подпись верна (подделанная): сообщение было изменено, подпись поддельная")
else:
    print("Подпись не верна (подделанная): проверка не пройдена")