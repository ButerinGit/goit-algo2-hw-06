import hashlib
from typing import Iterable, Dict, Any, List


class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        """
        size       — кількість бітів у фільтрі
        num_hashes — кількість хеш-функцій
        """
        if size <= 0:
            raise ValueError("size must be positive")
        if num_hashes <= 0:
            raise ValueError("num_hashes must be positive")

        self.size = size
        self.num_hashes = num_hashes
        # простий бітовий масив у вигляді списку 0/1
        self.bit_array: List[int] = [0] * size

    def _normalize(self, item: Any) -> str:
        """
        Нормалізуємо будь-яке значення до рядка.
        None → "" (порожній рядок).
        """
        return "" if item is None else str(item)

    def _hashes(self, item: Any):
        """
        Генерує num_hashes різних хешів для елемента.
        Використовуємо SHA-256 + індекс i як "сіль".
        """
        s = self._normalize(item)
        for i in range(self.num_hashes):
            data = (s + str(i)).encode("utf-8")
            digest = hashlib.sha256(data).hexdigest()
            h = int(digest, 16) % self.size
            yield h

    def add(self, item: Any) -> None:
        """Додає елемент до фільтра Блума."""
        for pos in self._hashes(item):
            self.bit_array[pos] = 1

    def __contains__(self, item: Any) -> bool:
        """
        Перевірка "можливо присутній".
        Якщо хоча б один біт 0 — точно немає.
        Якщо всі 1 — можливо є (фальш-позитиви можливі).
        """
        return all(self.bit_array[pos] for pos in self._hashes(item))


def check_password_uniqueness(
    bloom: BloomFilter, new_passwords: Iterable[Any]
) -> Dict[str, str]:
    """
    Перевіряє список паролів на унікальність відносно фільтра.
    Якщо пароль "новий" — додаємо його у фільтр.
    Повертає словник:
        { "пароль_як_рядок": "вже використаний"/"унікальний" }
    """
    results: Dict[str, str] = {}

    for pwd in new_passwords:
        already_used = pwd in bloom
        if already_used:
            status = "вже використаний"
        else:
            status = "унікальний"
            bloom.add(pwd)

        # ключ у словнику завжди рядок (навіть якщо було None / int)
        results[str(pwd)] = status

    return results


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")