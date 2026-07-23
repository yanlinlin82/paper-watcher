"""
Management command to generate the Excel export file with a date suffix.
Run after daily data updates to pre-build the downloadable file,
avoiding timeout issues during user download requests.
"""
import os
from datetime import date
from django.core.management.base import BaseCommand
from django.conf import settings
from openpyxl import Workbook
from core.models import Paper
from core.utils import load_fields


def format_impact_factor(impact_factor):
    if impact_factor is None or impact_factor == '':
        return '-'
    return str(impact_factor)


def generate_excel_file(output_path):
    fields_order, fields = load_fields()

    wb = Workbook(write_only=True)
    ws = wb.create_sheet(title="Papers")

    # 构建动态表头
    headers = ["标题", "杂志", "影响因子", "分区", "发表日期", "DOI", "PMID"]
    for field_key in fields_order:
        headers.append(fields[field_key]['name'])
    ws.append(headers)

    # 使用 prefetch_related 批量预取解析数据，避免 N+1 查询
    for paper in Paper.objects.all().prefetch_related('parseditem_set'):
        quartile_info = '-'
        if paper.journal_impact_factor_quartile:
            quartile_info = 'Q' + paper.journal_impact_factor_quartile

        # 从预取数据中构建字段查找表
        parsed_items = {item.key: (item.value or 'NA') for item in paper.parseditem_set.all()}

        row_data = [
            paper.title,
            paper.journal,
            format_impact_factor(paper.journal_impact_factor),
            quartile_info,
            paper.pub_date,
            paper.doi,
            paper.pmid,
        ]
        for field_key in fields_order:
            row_data.append(parsed_items.get(field_key, 'NA'))

        ws.append(row_data)

    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wb.save(output_path)
    return output_path


class Command(BaseCommand):
    help = 'Generate Excel file with all papers data'

    def handle(self, *args, **options):
        today = date.today().isoformat()
        output_dir = os.path.join(settings.BASE_DIR, 'output')
        output_path = os.path.join(output_dir, f'papers_{today}.xlsx')

        self.stdout.write(f"Generating Excel file: {output_path} ...")
        generate_excel_file(output_path)
        self.stdout.write(self.style.SUCCESS(f"Successfully generated: {output_path}"))
