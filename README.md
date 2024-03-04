# Шифрование и подпись данных

Этот скрипт реализует генерацию ключей, подписание и верификацию данных с использованием криптографии на эллиптических кривых.

## Требования

- Python 3.x
- cryptography

## Использование

1. Установите необходимые зависимости:
    ```bash
    pip install cryptography
    ```

2. Запустите скрипт:
    ```bash
    python main.py
    ```

## Описание

- `generate_keys()`: Генерирует приватный и публичный ключи.
- `sign_data(private_key, data)`: Подписывает данные с помощью приватного ключа.
- `verify_signature(public_key, data, signature)`: Проверяет подпись данных с помощью публичного ключа.

## Пример использования

1. Генерация ключей для пользователя и другой стороны.
2. Ввод сообщения для подписи.
3. Подписание сообщения пользователем.
4. Проверка подписи другой стороной.
5. Симуляция подделанной подписи для демонстрации.