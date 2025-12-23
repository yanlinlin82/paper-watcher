import os
import hashlib
import time
import datetime
import random
import string
import requests
import urllib
import base64
import qrcode
import json
import calendar
from io import BytesIO
from collections import Counter
from openpyxl import Workbook
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from django.shortcuts import render, redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from core.models import Paper, ParsedItem, Payment
from core.utils import load_fields, load_keywords
from config import settings


site_name = os.getenv('TITLE')
if site_name is None:
    raise Exception("ERROR: TITLE not set!")

keywords = load_keywords()

payment_price = float(os.getenv('PAYMENT_PRICE', '19.9'))
github_url = os.getenv('GITHUB_URL', 'https://github.com/yanlinlin82/paper-watcher')


fields_order, fields = load_fields()


def generate_order_id():
    timestamp = int(time.time())
    num_1 = int(timestamp / 100000)
    num_2 = timestamp % 100000
    num_3 = random.randint(1, 9999)
    return f"{num_1:05}-{num_2:05}-{num_3:04}"

def generate_sign(params, api_key):
    # 生成签名字符串
    stringA = '&'.join([f'{k}={params[k]}' for k in sorted(params)])
    stringSignTemp = f"{stringA}&key={api_key}"

    # 使用 MD5 生成签名
    sign = hashlib.md5(stringSignTemp.encode('utf-8')).hexdigest().upper()
    return sign

def generate_nonce_str(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_paginated_reviews(reviews, page_number):
    if page_number is None:
        page_number = 1

    p = Paginator(reviews, 20)
    try:
        reviews = p.get_page(page_number)
    except PageNotAnInteger:
        page_number = 1
        reviews = p.page(1)
    except EmptyPage:
        page_number = p.num_pages
        reviews = p.page(p.num_pages)

    items = list(reviews)
    indices = list(range((reviews.number - 1) * p.per_page + 1, reviews.number * p.per_page + 1))

    return reviews, zip(items, indices)

def format_impact_factor(impact_factor):
    if impact_factor is None:
        return None
    if impact_factor < 0.1:
        return "<0.1"
    return f"{impact_factor:.1f}"

def to_number(s):
    try:
        return float(s)
    except ValueError:
        return ''

from core.query import tokenize, parse

def get_parsed_value(paper, key, default='NA'):
    """获取指定paper的解析值"""
    try:
        parsed_item = paper.parseditem_set.get(key=key)
        return parsed_item.value or default
    except ParsedItem.DoesNotExist:
        return default

def get_parsed_values_for_paper(paper, keys):
    """批量获取指定paper的多个解析值"""
    parsed_items = {item.key: item.value or 'NA' for item in paper.parseditem_set.filter(key__in=keys)}
    return {key: parsed_items.get(key, 'NA') for key in keys}

def get_all_parsed_values(paper):
    """获取指定paper的所有解析值"""
    return {item.key: item.value or 'NA' for item in paper.parseditem_set.all()}

def build_query(parsed_query):
    if not parsed_query:
        return Q()

    query = Q()
    current_operator = None

    for token in parsed_query:
        if isinstance(token, list):
            # 递归处理嵌套表达式
            subquery = build_query(token)
            if current_operator == 'AND' or current_operator is None:
                query &= subquery
            elif current_operator == 'OR':
                query |= subquery
        elif token in {'AND', 'OR', 'NOT'}:
            current_operator = token
        else:
            # 构建单个字段查询的Q对象
            # 基础字段查询
            q_obj = (
                Q(title__icontains=token) |
                Q(journal__icontains=token) |
                Q(doi=token) |
                Q(pmid=token)
            )
            
            # 动态添加解析字段查询
            for field_key in fields_order:
                q_obj |= Q(parseditem__key=field_key, parseditem__value__icontains=token)
            if current_operator == 'NOT':
                q_obj = ~q_obj

            if current_operator == 'AND' or current_operator is None:
                query &= q_obj
            elif current_operator == 'OR':
                query |= q_obj

    return query

def home(request):
    papers = Paper.objects.all()

    filter_quantile = request.GET.get('fq') or ''
    if filter_quantile == '1':
        papers = papers.filter(journal_impact_factor_quartile='1')
    elif filter_quantile == '2':
        papers = papers.filter(journal_impact_factor_quartile__lte='2')
    elif filter_quantile == '3':
        papers = papers.filter(journal_impact_factor_quartile__lte='3')
    else:
        filter_quantile = ''

    filter_impact_factor = request.GET.get('fi') or ''
    impact_factor_min, impact_factor_max = '', ''
    if filter_impact_factor:
        values = (filter_impact_factor.split('-') + [''])[:2]
        impact_factor_min = to_number(values[0])
        impact_factor_max = to_number(values[1])
    if impact_factor_min != '':
        papers = papers.filter(journal_impact_factor__gte=impact_factor_min)
    if impact_factor_max != '':
        papers = papers.filter(journal_impact_factor__lte=impact_factor_max)

    filter_pub_date = request.GET.get('fd') or ''
    pub_date_start, pub_date_end = None, None
    if filter_pub_date:
        values = (filter_pub_date.split('-') + [''])[:2]
        if values[0] != '':
            if len(values[0]) == 4:
                pub_date_start = datetime.datetime.strptime(values[0] + '0101', '%Y%m%d')
            elif len(values[0]) == 6:
                pub_date_start = datetime.datetime.strptime(values[0] + '01', '%Y%m%d')
        if values[1] != '':
            if len(values[1]) == 4:
                pub_date_end = datetime.datetime.strptime(values[1] + '1231', '%Y%m%d')
            elif len(values[1]) == 6:
                year_month = values[1]
                year = int(year_month[:4])
                month = int(year_month[4:])
                last_day = calendar.monthrange(year, month)[1]
                pub_date_end = datetime.datetime(year, month, last_day)
    if pub_date_start is not None and pub_date_end is not None:
        if pub_date_start > pub_date_end:
            pub_date_start, pub_date_end = pub_date_end, pub_date_start
    if pub_date_start is not None:
        papers = papers.filter(pub_date_dt__gte=pub_date_start)
    if pub_date_end is not None:
        papers = papers.filter(pub_date_dt__lte=pub_date_end)

    query = request.GET.get('q') or ''
    if query:
        tokens = tokenize(query)
        parsed_query = parse(tokens)
        q_obj = build_query(parsed_query)
        papers = papers.filter(q_obj).distinct()

    papers = papers.order_by('-source', '-pub_date_dt')

    page_number = request.GET.get('page')
    papers, items = get_paginated_reviews(papers, page_number)

    get_params = request.GET.copy()
    if 'page' in get_params:
        del get_params['page']

    # 使用动态字段配置
    parsed_keys = fields_order
    
    for index, paper in enumerate(papers):
        paper.index = index + papers.start_index()
        if paper.parse_time is None:
            paper.parse_time = paper.created
        
        # 批量获取解析数据并设置到paper对象上
        parsed_data = get_parsed_values_for_paper(paper, parsed_keys)
        for key, value in parsed_data.items():
            setattr(paper, key, value)
        
        paper.journal_impact_factor = format_impact_factor(paper.journal_impact_factor)

    # 构造动态字段的表头数据
    dynamic_headers = []
    for field_key in fields_order:
        field_info = fields[field_key]
        dynamic_headers.append({
            'key': field_key,
            'name': field_info['name']
        })
    
    # 为每个 paper 构造包含字段值的数据结构
    papers_with_data = []
    for paper in papers:
        # 获取该 paper 的所有动态字段值
        dynamic_values = []
        for field_key in fields_order:
            field_value = getattr(paper, field_key, 'NA')
            dynamic_values.append(field_value)
        
        # 构造包含动态字段值的 paper 数据
        paper_data = {
            'paper': paper,
            'dynamic_values': dynamic_values
        }
        papers_with_data.append(paper_data)
    
    return render(request, 'core/home.html', {
        'site_name': site_name,
        'keywords': keywords,
        'github_url': github_url,
        'payment_price': payment_price,
        'query': query,
        'filter_quantile': filter_quantile,
        'impact_factor_min': impact_factor_min,
        'impact_factor_max': impact_factor_max,
        'pub_date_start': pub_date_start.strftime('%Y%m') if pub_date_start else '',
        'pub_date_end': pub_date_end.strftime('%Y%m') if pub_date_end else '',
        'get_params': get_params,
        'papers': papers,
        'items': items,
        'dynamic_headers': dynamic_headers,
        'papers_with_data': papers_with_data,
    })

def stat(request):
    papers = Paper.objects.all().order_by('-pub_date_dt')
    year_counts = Counter([paper.pub_date_dt.year for paper in papers])
    month_counts = Counter([f"{paper.pub_date_dt.year}-{paper.pub_date_dt.month:02}" for paper in papers])

    years = sorted(year_counts.keys(), reverse=True)  # 获取所有年份并按倒序排列
    months = [f"{i:02d}" for i in range(1, 13)]  # 生成月份列表

    # 构造一个包含所有数据的二级列表
    data = []
    for year in years:
        year_data = {'year': year, 'total': year_counts[year], 'months': []}
        for month in months:
            count = month_counts.get(f"{year}-{month}", 0)
            year_data['months'].append({'month': month, 'count': count})
        data.append(year_data)

    context = {
        'site_name': site_name,
        'data': data,
        'months': months,
    }
    return render(request, 'core/stat.html', context)

def all_papers_to_excel():
    wb = Workbook()
    ws = wb.active
    ws.title = "Papers"
    # 构建动态表头
    headers = ["标题", "杂志", "影响因子", "分区", "发表日期", "DOI", "PMID"]
    # 添加动态字段的中文名称
    for field_key in fields_order:
        headers.append(fields[field_key]['name'])
    
    ws.append(headers)
    # 使用动态字段配置
    parsed_keys = fields_order
    
    for papers in Paper.objects.all():
        quartile_info = '-'
        if papers.journal_impact_factor_quartile:
            quartile_info = 'Q' + papers.journal_impact_factor_quartile
        
        # 批量获取解析数据
        parsed_data = get_parsed_values_for_paper(papers, parsed_keys)
        
        # 构建动态数据行
        row_data = [
            papers.title,
            papers.journal,
            format_impact_factor(papers.journal_impact_factor),
            quartile_info,
            papers.pub_date,
            papers.doi,
            papers.pmid,
        ]
        # 添加动态字段值
        for field_key in fields_order:
            row_data.append(parsed_data[field_key])
        
        ws.append(row_data)

    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = 'attachment; filename="papers.xlsx"'
    wb.save(response)
    return response

def get_cert_serial_no(cert_path):
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    serial_number = cert.serial_number
    cert_data = format(serial_number, 'x').upper()
    return cert_data

def generate_v3_headers(payload):
    apiclient_cert_file = os.path.join(settings.BASE_DIR, os.getenv('WEB_CERT_PATH'))
    apiclient_key_file = os.path.join(settings.BASE_DIR, os.getenv('WEB_KEY_PATH'))

    mchid = os.getenv('WEB_MERCHANT_ID')
    serial_no = get_cert_serial_no(apiclient_cert_file)
    timestamp = str(int(time.time()))
    nonce_str = generate_nonce_str()

    # 生成签名的字符串
    sign_str = f"POST\n/v3/pay/transactions/native\n{timestamp}\n{nonce_str}\n{payload}\n"

    # 加载私钥
    with open(apiclient_key_file, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # 签名
    signature = private_key.sign(
        sign_str.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature = base64.b64encode(signature).decode('utf-8')

    headers = {
        "Authorization": f'WECHATPAY2-SHA256-RSA2048 mchid="{mchid}",serial_no="{serial_no}",nonce_str="{nonce_str}",timestamp="{timestamp}",signature="{signature}"',
        "Content-Type": "application/json"
    }

    return headers

def wx_create_payment_order(order_number):
    apiclient_cert_file = os.path.join(settings.BASE_DIR, os.getenv('WEB_CERT_PATH'))
    apiclient_key_file = os.path.join(settings.BASE_DIR, os.getenv('WEB_KEY_PATH'))

    url = "https://api.mch.weixin.qq.com/v3/pay/transactions/native"
    payload = {
        "mchid": os.getenv('WEB_MERCHANT_ID'),
        "appid": os.getenv('WEB_MERCHANT_APP_ID'),
        "description": '购买后可随时下载最新数据表格（Excel文件）',
        "out_trade_no": order_number,  # 商户订单号
        "notify_url": f"https://{os.getenv('WEB_DOMAIN')}/wx_payment_callback/",  # 微信支付成功后通知的URL
        "amount": {
            "total": int(payment_price * 100), # 订单金额，单位为分
            "currency": "CNY"
        }
    }

    # 转换为JSON
    json_payload = json.dumps(payload)

    # 获取签名（使用你自己的签名函数）
    headers = generate_v3_headers(json_payload)

    # 发送请求
    try:
        response = requests.post(
            url,
            headers=headers,
            data=json_payload,
            cert=(
                apiclient_cert_file,
                apiclient_key_file
            )
        )
        if response.status_code != 200:
            error_detail = response.text if hasattr(response, 'text') else str(response.content)
            raise Exception(f"微信支付API调用失败 (状态码: {response.status_code}): {error_detail}")

        # 解析响应
        response_data = response.json()
        qr_code_url = response_data.get("code_url")
        if not qr_code_url:
            raise Exception(f"微信支付响应中未找到code_url字段: {response_data}")
        return qr_code_url
    except requests.exceptions.RequestException as e:
        raise Exception(f"请求微信支付API时发生网络错误: {str(e)}")
    except json.JSONDecodeError as e:
        raise Exception(f"解析微信支付响应JSON失败: {str(e)}")

def wx_create_payment(request):
    print(f"wx_create_payment: {request.method}")
    if request.method != 'POST':
        return HttpResponseBadRequest("Invalid request method")

    print(f"wx_create_payment: {request.user}")
    try:
        payment = Payment.objects.get(user=request.user)
        if payment.has_paid:
            return JsonResponse({
                "qr_image": None,
                "message": "Payment already completed",
            })

        # 发起微信支付请求并获取支付二维码的URL
        qr_url = wx_create_payment_order(payment.order_number)

        if not qr_url:
            return JsonResponse({
                "error": "Failed to generate QR code URL",
            }, status=500)

        # 生成二维码
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_url)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')

        # 将二维码图像转换为Base64编码
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        # 返回二维码图像的Base64字符串
        return JsonResponse({
            "qr_image": img_str,
        })
    except Payment.DoesNotExist:
        return JsonResponse({
            "error": "Payment record not found",
        }, status=404)
    except Exception as e:
        import traceback
        error_message = str(e)
        error_traceback = traceback.format_exc()
        print(f"Error in wx_create_payment: {error_message}")
        print(f"Traceback: {error_traceback}")
        return JsonResponse({
            "error": f"Failed to create payment: {error_message}",
        }, status=500)

def decrypt_wechat_ciphertext(api_key, associated_data, nonce, ciphertext):
    # Base64 decode the ciphertext
    ciphertext = base64.b64decode(ciphertext)

    # Prepare the AES cipher
    cipher = AES.new(api_key.encode('utf-8'), AES.MODE_GCM, nonce=nonce.encode('utf-8'))
    cipher.update(associated_data.encode('utf-8'))

    # Separate the encrypted data and the tag
    encrypted_data = ciphertext[:-16]
    tag = ciphertext[-16:]

    # Decrypt and verify the data
    try:
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        return decrypted_data.decode('utf-8')
    except ValueError as e:
        print("Incorrect decryption", e)
        return None

@csrf_exempt
def wx_payment_callback(request):
    #print(f"wx_payment_callback: {request.body}")
    # b'{"id":"4b******-****-****-****-************","create_time":"2024-08-10T17:54:45+08:00","resource_type":"encrypt-resource","event_type":"TRANSACTION.SUCCESS","summary":"\\xe6\\x94\\xaf\\xe4\\xbb\\x98\\xe6\\x88\\x90\\xe5\\x8a\\x9f","resource":{"original_type":"transaction","algorithm":"AEAD_AES_256_GCM","ciphertext":"pb***********==","associated_data":"transaction","nonce":"xTPC24lW00hr"}}'
    if request.method != 'POST':
        return HttpResponseBadRequest("Invalid request method")

    data = json.loads(request.body)
    event_type = data.get('event_type')

    if event_type != "TRANSACTION.SUCCESS":
        return HttpResponse("Invalid event type", status=400)

    if data.get('resource').get('algorithm') != "AEAD_AES_256_GCM":
        return HttpResponse("Invalid algorithm", status=400)

    api_key = os.getenv('WEB_API_V3_KEY')
    associated_data = data["resource"]["associated_data"]
    nonce = data["resource"]["nonce"]
    ciphertext = data["resource"]["ciphertext"]
    decrypted_data = decrypt_wechat_ciphertext(api_key, associated_data, nonce, ciphertext)
    #print(f"Decrypted data: {decrypted_data}")
    # {"mchid":"16******","appid":"wx2d*******","out_trade_no":"17***-*****-****","transaction_id":"42************","trade_type":"NATIVE","trade_state":"SUCCESS","trade_state_desc":"\xe6\x94\xaf\xe4\xbb\x98\xe6\x88\x90\xe5\x8a\x9f","bank_type":"CMB_CREDIT","attach":"","success_time":"2024-08-10T18:09:52+08:00","payer":{"openid":"ox******"},"amount":{"total":1000,"payer_total":1000,"currency":"CNY","payer_currency":"CNY"}}

    json_data = json.loads(decrypted_data)
    if json_data.get('trade_state') != 'SUCCESS':
        return HttpResponse("Invalid trade state", status=400)

    mchid = json_data.get('mchid')
    appid = json_data.get('appid')
    if mchid != os.getenv('WEB_MERCHANT_ID') or appid != os.getenv('WEB_MERCHANT_APP_ID'):
        return HttpResponse("Invalid merchant ID or app ID", status=400)

    out_trade_no = json_data.get('out_trade_no')
    payment_list = Payment.objects.filter(order_number=out_trade_no)
    if payment_list.count() == 0:
        return HttpResponse("Order not found", status=404)
    payment = payment_list[0]
    payment.has_paid = True
    payment.paid_amount = json_data['amount']['total'] / 100
    payment.payment_date = datetime.datetime.strptime(json_data['success_time'], "%Y-%m-%dT%H:%M:%S%z")
    payment.payment_callback = json.dumps(json_data)
    payment.save()

    return HttpResponse("Success", status=200)

def generate_state():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def wx_get_qr_code(request):
    state = generate_state()
    request.session['wx_state'] = state

    weixin_auth_url = "https://open.weixin.qq.com/connect/qrconnect"
    params = {
        "appid": os.getenv('WEB_APP_ID'),
        "redirect_uri": f'https://{os.getenv("WEB_DOMAIN")}/wx_login_callback/',
        "response_type": "code",
        "scope": "snsapi_login",
        "state": state
    }
    auth_url = f"{weixin_auth_url}?{urllib.parse.urlencode(params)}#wechat_redirect"
    return JsonResponse({'url': auth_url})

def get_openid(code):
    APP_ID = os.getenv('WEB_APP_ID')
    SECRET = os.getenv('WEB_APP_SECRET')
    if not APP_ID or not SECRET:
        print(f"Invalid APP_ID or SECRET: '{APP_ID}', '{SECRET}'")
        return None

    url = "https://api.weixin.qq.com/sns/oauth2/access_token"
    params = {
        "appid": APP_ID,
        "secret": SECRET,
        "code": code,
        "grant_type": "authorization_code"
    }
    response = requests.get(url, params=params)
    if response.status_code != 200:
        print(f"Failed to get session_key: {response.text}")
        return None
    json_data = response.json()
    if json_data.get('errcode', 0) != 0:
        print(f"Failed to get session_key: {response.text}")
        return None

    openid = json_data.get('openid')
    return openid

def wx_login_callback(request):
    received_state = request.GET.get('state')
    code = request.GET.get('code')

    # 从会话中获取原始 state
    original_state = request.session.get('wx_state')

    # 验证 state
    if not original_state or received_state != original_state:
        return HttpResponseBadRequest("Invalid state parameter")

    # state 验证通过，可以继续处理 code 并向微信请求 access_token
    # 您可以在此处向微信服务器发出请求，使用 code 获取 access_token 和 openid
    openid = get_openid(code)
    if not openid:
        return HttpResponseBadRequest("Login failed")

    if request.user.is_authenticated:
        user = request.user
    else:
        # 如果用户未登录，尝试查找或创建用户
        user, created = User.objects.get_or_create(username=openid)
        if created:
            # 可以在这里设置默认密码，或者使用随机密码
            user.set_unusable_password()
            user.save()

    payment_list = Payment.objects.filter(openid=openid)
    if payment_list.count() == 0:
        payment = Payment(user=user, openid=openid)
        payment.order_number = generate_order_id()
        payment.save()
    else:
        payment = payment_list[0]
        if payment.order_number is None:
            payment.order_number = generate_order_id()
            payment.save()

    login(request, user)

    # 清理 session 中的 state 以防止重用
    del request.session['wx_state']

    return redirect('download')

def download(request):
    user = request.user
    if not user.is_authenticated:
        return render(request, 'core/login.html', {
            'site_name': site_name,
            'payment_price': payment_price,
        })

    payment = Payment.objects.get(user=user)
    if not payment.has_paid:
        payment.order_number = generate_order_id()
        payment.save()
        return render(request, 'core/payment.html', {
            'site_name': site_name,
            'order_number': payment.order_number,
            'payment_price': payment_price,
        })

    if request.method == 'POST':
        if request.POST.get('csrfmiddlewaretoken'):
            return all_papers_to_excel()

    return render(request, 'core/download.html', {
        'site_name': site_name,
        'payment_price': payment_price,
    })

def do_logout(request):
    logout(request)
    return redirect('home')
