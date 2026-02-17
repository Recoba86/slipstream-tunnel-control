<div dir="rtl">

# slipstream-tunnel

[English](README.md) | **فارسی**

راه‌اندازی تونل DNS با slipstream و اسکن خودکار سرورهای DNS توسط dnscan.

## شروع سریع

### سرور (خارج از ایران)

</div>

```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/nightowlnerd/slipstream-tunnel/main/install.sh) server
```

<div dir="rtl">

دستورات را دنبال کنید تا DNS کلودفلر را تنظیم کنید.

### کلاینت (داخل ایران)

</div>

```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/nightowlnerd/slipstream-tunnel/main/install.sh) client
```

<div dir="rtl">

بعد از نصب، دستور `slipstream-tunnel` در سیستم موجود است.

### حالت آفلاین

اگر شبکه بسته است، ابتدا باینری‌ها را دانلود کرده سپس مسیر آنها را بدهید:

</div>

```bash
slipstream-tunnel client --dnscan ./dnscan.tar.gz --slipstream ./slipstream-client
```

<div dir="rtl">

## پیش‌نیازها

### سرور
- VPS با دسترسی root
- دامنه با DNS کلودفلر
- پنل 3x-ui نصب شده (یا هر پنل V2ray)

### کلاینت
- ماشین لینوکس با دسترسی root
- برای حالت آفلاین:
  - [dnscan releases](https://github.com/nightowlnerd/dnscan/releases)
  - [slipstream releases](https://github.com/nightowlnerd/slipstream-rust/releases)

از [فورک slipstream-rust](https://github.com/nightowlnerd/slipstream-rust) با رفع باگ‌های مصرف CPU و قطع اتصال استفاده می‌کند. ریپوی اصلی دیگر فعال نیست.

## دستورات

</div>

```bash
slipstream-tunnel server    # راه‌اندازی سرور
slipstream-tunnel client    # راه‌اندازی کلاینت
slipstream-tunnel status    # نمایش وضعیت
slipstream-tunnel logs      # مشاهده لاگ (با -f برای دنبال کردن)
slipstream-tunnel health    # بررسی DNS و تعویض اگر کند باشد
slipstream-tunnel rescan    # اسکن دستی DNS و تعویض به بهترین
slipstream-tunnel dashboard # داشبورد کوچک کلاینت
slipstream-tunnel menu      # منوی مانیتورینگ دستی
sst                         # دستور کوتاه برای باز کردن منوی کلاینت
slipstream-tunnel remove    # حذف همه چیز
```

<div dir="rtl">

## گزینه‌ها

| گزینه | توضیح |
|-------|-------|
| `--domain` | دامنه تونل (مثلاً t.example.com) |
| `--port` | سرور: پورت هدف / کلاینت: پورت شنود |
| `--dns-file` | لیست سرورهای DNS (بدون اسکن subnet) |
| `--dnscan` | مسیر فایل dnscan (حالت آفلاین) |
| `--slipstream` | مسیر باینری slipstream (حالت آفلاین) |
| `--manage-resolver` | اجازه تغییر resolver روی سرور |

## نحوه کار

### راه‌اندازی سرور

1. راهنمای تنظیم DNS کلودفلر (رکوردهای A و NS)
2. تأیید DNS با `dig`
3. تولید گواهی SSL
4. دانلود و نصب باینری slipstream-server
5. ساخت و شروع سرویس systemd

### راه‌اندازی کلاینت

1. دانلود باینری‌های dnscan و slipstream (کش برای استفاده مجدد)
2. درخواست پورت تونل کلاینت (پیش‌فرض: 7000)
3. درخواست تنظیمات اسکن (کشور، حالت، تعداد worker، timeout)
4. اسکن و تأیید سرورهای DNS با اتصال واقعی تونل
5. انتخاب سریع‌ترین سرور تأیید شده و شروع slipstream-client
6. تنظیم بررسی سلامت هر ساعت و باز کردن منوی مانیتورینگ

### بررسی سلامت

- هر ساعت اجرا می‌شود
- تأخیر سرور DNS فعلی را تست می‌کند
- اگر تأخیر > 1000ms باشد، به سرور بهتر تغییر می‌دهد
- لاگ در `~/.tunnel/health.log`

## فایل‌ها

</div>

```
~/.tunnel/
├── config          # تنظیمات فعلی
├── servers.txt     # سرورهای DNS تأیید شده
├── health.log      # تاریخچه بررسی سلامت
└── dnscan/         # باینری و داده dnscan
```

<div dir="rtl">

## تنظیم x-ui

بعد از اجرای اسکریپت روی سرور و کلاینت:

1. **پنل x-ui را باز کنید** روی سرور (3x-ui، x-ui و غیره)

2. **یک inbound بسازید** روی پورت slipstream سرور
   - پورت: `2053` (یا مقدار `--port` شما)
   - پروتکل: VLESS/VMess/...

3. **External proxy اضافه کنید** به inbound
   - Host: آدرس IP سرور ایران
   - پورت: `7000` (یا مقدار `--port` کلاینت)

4. **کانفیگ را export کنید** و در اپ V2Ray استفاده کنید

## عیب‌یابی

**سرور: "DNS not configured"**
- رکوردهای DNS کلودفلر را بررسی کنید
- ۵ دقیقه صبر کنید تا DNS منتشر شود
- تأیید با: `dig NS t.example.com`

**کلاینت: "No DNS servers passed verification"**
- آیا سرور در حال اجراست؟ `systemctl status slipstream-server`
- آیا پورت 53 روی سرور باز است؟
- بررسی لاگ سرور: `journalctl -u slipstream-server -f`

**کلاینت: "Cannot download"**
- شبکه بسته است
- از حالت آفلاین با `--dnscan` و `--slipstream` استفاده کنید
- باینری‌ها را دانلود کنید:
  - https://github.com/nightowlnerd/dnscan/releases
  - https://github.com/nightowlnerd/slipstream-rust/releases

</div>
