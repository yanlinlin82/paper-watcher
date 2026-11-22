import os
import sqlite3
from datetime import date
from decimal import Decimal

# `core.views` raises at import time unless these are set. The URLconf (and thus
# views) is imported lazily on the first request, so setting them here keeps the
# test suite independent of the developer's .env file.
os.environ.setdefault('TITLE', 'test-site')
os.environ.setdefault('KEYWORDS_FILE', 'data/biomed-dl/keywords.txt')
os.environ.setdefault('FIELDS_FILE', 'data/biomed-dl/fields.tsv')

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


class HomePaginationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        Paper.objects.bulk_create([
            Paper(
                title=f'paper {i}',
                source=f'src{i:03d}',
                pub_date_dt=date(2024, 1, 1),
            )
            for i in range(30)
        ])

    def get_page(self, **params):
        return self.client.get('/', params, SERVER_NAME='localhost')

    def test_first_page_renders(self):
        response = self.get_page(page=1)
        self.assertEqual(response.status_code, 200)

    def test_default_page_is_first(self):
        response = self.client.get('/', SERVER_NAME='localhost')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['papers'].number, 1)

    def test_last_page_renders(self):
        response = self.get_page(page=2)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['papers'].number, 2)

    def test_page_beyond_last_returns_404(self):
        # Crawlers used to receive 200 + the last page here, which kept them
        # enumerating deeper pages. Out-of-range must be a hard 404.
        self.assertEqual(self.get_page(page=3).status_code, 404)

    def test_page_zero_returns_404(self):
        self.assertEqual(self.get_page(page=0).status_code, 404)

    def test_negative_page_returns_404(self):
        self.assertEqual(self.get_page(page=-1).status_code, 404)

    def test_non_integer_page_returns_404(self):
        self.assertEqual(self.get_page(page='abc').status_code, 404)

    def test_absurd_page_returns_404(self):
        self.assertEqual(self.get_page(page='1038895040').status_code, 404)


class HomeEmptyDatabaseTests(TestCase):
    def test_first_page_renders(self):
        response = self.client.get('/', SERVER_NAME='localhost')
        self.assertEqual(response.status_code, 200)

    def test_second_page_returns_404(self):
        response = self.client.get('/', {'page': 2}, SERVER_NAME='localhost')
        self.assertEqual(response.status_code, 404)


class PaperIndexTests(SimpleTestCase):
    def test_source_pub_date_index_declared(self):
        declared = [tuple(index.fields) for index in Paper._meta.indexes]
        self.assertIn(('source', 'pub_date_dt'), declared)


class PaperIndexDatabaseTests(TestCase):
    def test_index_created_by_migrations(self):
        if connection.vendor != 'sqlite':
            self.skipTest('SQLite-specific schema check')
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='index' AND tbl_name='core_paper'"
            )
            names = {row[0] for row in cursor.fetchall()}
        self.assertIn('core_paper_src_date', names)
