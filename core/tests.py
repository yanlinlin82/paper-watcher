import sqlite3
from decimal import Decimal

from django.db import connection
from django.test import SimpleTestCase, TestCase

from core.management.commands.generate_excel import (
    PREFETCH_BATCH_SIZE,
    iter_papers_with_items,
)
from core.models import Paper
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


class IterPapersWithItemsTests(TestCase):
    def test_prefetch_stays_within_sqlite_variable_limit(self):
        # Regression: prefetching every paper in one query exceeded SQLite's
        # bound-variable limit on the production database ("too many SQL
        # variables"). Lower the limit to its historical default so an
        # unbounded prefetch fails here as well.
        paper_count = PREFETCH_BATCH_SIZE * 2 + 200
        Paper.objects.bulk_create([
            Paper(title=f'paper {i}') for i in range(paper_count)
        ])

        connection.ensure_connection()
        getlimit = connection.connection.getlimit
        setlimit = connection.connection.setlimit
        original = getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER)
        self.addCleanup(setlimit, sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, original)
        setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)

        papers = list(iter_papers_with_items())

        self.assertEqual(len(papers), paper_count)
        for paper in papers:
            self.assertIn('parseditem_set', paper._prefetched_objects_cache)
