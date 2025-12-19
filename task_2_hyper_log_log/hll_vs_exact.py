import hashlib
import math
import re
from time import perf_counter
from typing import Iterable, List, Tuple


class HyperLogLog:
    """
    Спрощена реалізація HyperLogLog для оцінки кількості унікальних елементів.
    """

    MAX_BITS = 64

    def __init__(self, p: int = 14):
        """
        p — кількість бітів для індексу регістру (2**p регістрів).
        Типові значення: 4..16.
        m = 2**p — кількість регістрів.
        """
        if not (4 <= p <= 16):
            raise ValueError("p must be in [4, 16]")
        self.p = p
        self.m = 1 << p
        self.registers: List[int] = [0] * self.m

    def _hash(self, value) -> int:
        """
        Хешуємо значення у 64-бітне число за допомогою SHA-1.
        """
        data = str(value).encode("utf-8")
        digest = hashlib.sha1(data).hexdigest()
        h = int(digest, 16) & ((1 << self.MAX_BITS) - 1)
        return h

    def _rho(self, w: int) -> int:
        """
        rho(w): кількість початкових нулів + 1 у (MAX_BITS - p)-бітному числі w.
        """
        bits = self.MAX_BITS - self.p
        if w == 0:
            return bits + 1
        leading_zeros = bits - w.bit_length()
        return leading_zeros + 1

    def add(self, value) -> None:
        """
        Додає елемент до структури HyperLogLog.
        """
        x = self._hash(value)
        # старші p бітів — індекс регістру
        idx = x >> (self.MAX_BITS - self.p)
        # решта бітів — для обчислення rho
        w = x & ((1 << (self.MAX_BITS - self.p)) - 1)
        rho = self._rho(w)
        if rho > self.registers[idx]:
            self.registers[idx] = rho

    def count(self) -> float:
        """
        Повертає оцінку кількості унікальних елементів.
        """
        m = self.m
        registers = self.registers

        # константа alpha_m
        if m == 16:
            alpha_m = 0.673
        elif m == 32:
            alpha_m = 0.697
        elif m == 64:
            alpha_m = 0.709
        else:
            alpha_m = 0.7213 / (1 + 1.079 / m)

        # сира оцінка
        Z = sum(2.0 ** -v for v in registers)
        E = alpha_m * (m ** 2) / Z

        # мала кількість елементів — корекція (лініаризація)
        V = registers.count(0)
        if E <= 5.0 * m / 2.0 and V != 0:
            E = m * math.log(m / V)

        # дуже великі кардинальності (майже не потрібна в реальних логах)
        TWO_32 = float(1 << 32)
        if E > (TWO_32 / 30.0):
            E = -TWO_32 * math.log(1.0 - E / TWO_32)

        return E


# Простий парсер IPv4-адрес
IPV4_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def load_ips_from_log(path: str) -> List[str]:
    """
    Завантажує IP-адреси з лог-файлу.
    Некоректні рядки (де немає IP) ігноруються.
    """
    ips: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = IPV4_REGEX.search(line)
            if not m:
                # некоректний рядок — ігноруємо
                continue
            ips.append(m.group(1))
    return ips


def exact_unique_count(ips: Iterable[str]) -> int:
    """Точний підрахунок унікальних IP за допомогою set."""
    return len(set(ips))


def measure_exact(ips: List[str]) -> Tuple[int, float]:
    start = perf_counter()
    cnt = exact_unique_count(ips)
    elapsed = perf_counter() - start
    return cnt, elapsed


def measure_hll(ips: List[str], p: int = 14) -> Tuple[float, float]:
    hll = HyperLogLog(p=p)
    start = perf_counter()
    for ip in ips:
        hll.add(ip)
    estimate = hll.count()
    elapsed = perf_counter() - start
    return estimate, elapsed


def print_comparison_table(
    exact_cnt: int,
    exact_time: float,
    hll_cnt: float,
    hll_time: float,
) -> None:
    error = abs(hll_cnt - exact_cnt) / exact_cnt * 100 if exact_cnt > 0 else 0.0

    print("\nРезультати порівняння:")
    header = f"{'Метод':<25}{'Унікальні елементи':>20}{'Час виконання (сек.)':>25}"
    print(header)
    print("-" * len(header))
    print(f"{'Точний підрахунок':<25}{exact_cnt:>20.1f}{exact_time:>25.4f}")
    print(f"{'HyperLogLog':<25}{hll_cnt:>20.1f}{hll_time:>25.4f}")
    print(f"\nВідносна похибка HyperLogLog: {error:.4f}%")


if __name__ == "__main__":
    LOG_PATH = "lms-stage-access.log"

    # 1. Завантаження даних
    ips = load_ips_from_log(LOG_PATH)
    print(f"Загальна кількість рядків з IP: {len(ips)}")

    # 2. Точний підрахунок
    exact_cnt, exact_time = measure_exact(ips)

    # 3. HyperLogLog
    hll_cnt, hll_time = measure_hll(ips, p=14)

    # 4. Вивід таблиці
    print_comparison_table(exact_cnt, exact_time, hll_cnt, hll_time)