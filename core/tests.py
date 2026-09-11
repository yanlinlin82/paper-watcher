from decimal import Decimal

from django.test import SimpleTestCase

from core.utils import price_to_cents


class PriceToCentsTests(SimpleTestCase):
    def test_reported_bug_19_9_yuan(self):
        # Regression: int(float('19.9') * 100) == 1989, so a 19.9-yuan order
        # was charged 19.89 yuan. It must be exactly 1990 cents.
        self.assertEqual(price_to_cents('19.9'), 1990)

    def test_two_decimal_prices(self):
        cases = [
            ('0.01', 1),
            ('0.1', 10),
            ('1', 100),
            ('8.7', 870),
            ('19.90', 1990),
            ('19.99', 1999),
            ('100', 10000),
        ]
        for price, cents in cases:
            with self.subTest(price=price):
                self.assertEqual(price_to_cents(price), cents)

    def test_accepts_float_and_decimal(self):
        self.assertEqual(price_to_cents(19.9), 1990)
        self.assertEqual(price_to_cents(Decimal('19.9')), 1990)

    def test_rounds_half_up(self):
        self.assertEqual(price_to_cents('19.994'), 1999)
        self.assertEqual(price_to_cents('19.995'), 2000)
