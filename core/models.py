from django.db import models
from django.contrib.auth.models import User

class Journal(models.Model):
    name = models.CharField(max_length=512, unique=True)
    abbreviation = models.CharField(max_length=32, unique=True)
    impact_factor = models.DecimalField(max_digits=6, decimal_places=3, null=True, blank=True, default=None)
    impact_factor_year = models.IntegerField(null=True, blank=True, default=None)
    impact_factor_quartile = models.CharField(max_length=1, null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.name} - {self.abbreviation}"

class Paper(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    source = models.CharField(max_length=32, null=True, blank=True, default='')
    parse_time = models.DateTimeField(null=True, blank=True, default=None)

    title = models.CharField(max_length=512)
    journal = models.CharField(max_length=512, null=True, blank=True, default='')
    journal_abbreviation = models.CharField(max_length=32, null=True, blank=True, default='')
    journal_impact_factor = models.DecimalField(max_digits=6, decimal_places=3, null=True, blank=True, default=None)
    journal_impact_factor_quartile = models.CharField(max_length=1, null=True, blank=True, default='')
    pub_date = models.CharField(max_length=32, null=True, blank=True, default='')
    pub_date_dt = models.DateField(null=True, blank=True, default=None)
    pub_year = models.IntegerField(null=True, blank=True, default=None)
    doi = models.CharField(max_length=128, null=True, blank=True, default='')
    pmid = models.CharField(max_length=32, null=True, blank=True, default='')
    abstract = models.TextField(null=True, blank=True, default='')

    class Meta:
        # 列表页固定按 (source, pub_date_dt) 倒序取前 N 条。缺少这个复合索引时，
        # SQLite 每次请求都要对整张表做全量排序（USE TEMP B-TREE FOR ORDER BY），
        # 深层分页还要再跳过数万行，单请求耗时可达数十秒。
        # 升序索引可被反向扫描，直接给出 ORDER BY source DESC, pub_date_dt DESC 的顺序，
        # 配合 LIMIT 提前终止，首页与深页都能回到毫秒级。
        indexes = [
            models.Index(fields=['source', 'pub_date_dt'], name='core_paper_src_date'),
        ]

    def __str__(self):
        return f"{self.pub_year} - {self.journal} - {self.title}"

class ParsedItem(models.Model):
    paper = models.ForeignKey(Paper, on_delete=models.CASCADE)
    key = models.CharField(max_length=255)
    value = models.TextField(null=True, blank=True, default='')
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.paper.pmid} - {self.paper.title} - {self.key}"

class Payment(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    openid = models.CharField(max_length=128, null=True, blank=True)
    order_number = models.CharField(max_length=64, unique=True, null=True, blank=True, default=None)
    has_paid = models.BooleanField(default=False)
    paid_amount = models.DecimalField(max_digits=8, decimal_places=2, null=True, blank=True, default=None)
    payment_date = models.DateTimeField(null=True, blank=True)
    payment_callback = models.TextField(null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.user.username} - {'Paid' if self.has_paid else 'Not Paid'}"
