<div dir="rtl">

# slipstream-tunnel

[English](README.md) | **فارسی**

راه‌اندازی تونل DNS با slipstream و اسکن خودکار سرورهای DNS توسط dnscan.

## شروع سریع

### سرور (خارج از ایران)

</div>

```bash
curl -O https://raw.githubusercontent.com/nightowlnerd/dns-tunnel-setup/main/dns-tunnel.sh
chmod +x dns-tunnel.sh
./dns-tunnel.sh server
```

<div dir="rtl">

دستورات را دنبال کنید تا DNS کلودفلر را تنظیم کنید.

### کلاینت (داخل ایران)

</div>

```bash
# اگر شبکه باز است:
curl -O https://raw.githubusercontent.com/nightowlnerd/dns-tunnel-setup/main/dns-tunnel.sh
chmod +x dns-tunnel.sh
./dns-tunnel.sh client

# اگر شبکه بسته است (حالت آفلاین):
./dns-tunnel.sh client --dnscan ./dnscan-linux-amd64.tar.gz --slipstream ./slipstream-client-linux-amd64
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
  - [slipstream releases](https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases)

## دستورات

</div>

```bash
./dns-tunnel.sh server              # راه‌اندازی سرور
./dns-tunnel.sh client              # راه‌اندازی کلاینت
./dns-tunnel.sh status              # نمایش وضعیت
./dns-tunnel.sh health              # بررسی DNS و تعویض اگر کند باشد
./dns-tunnel.sh remove              # حذف همه چیز
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
| `--docker` | استفاده از Docker به جای باینری |

## نحوه کار

### راه‌اندازی سرور

1. راهنمای تنظیم DNS کلودفلر (رکوردهای A و NS)
2. تأیید DNS با `dig`
3. تولید گواهی SSL
4. دانلود و نصب باینری slipstream-server
5. ساخت و شروع سرویس systemd

### راه‌اندازی کلاینت

1. دانلود باینری‌های dnscan و slipstream (کش برای استفاده مجدد)
2. درخواست تنظیمات اسکن (کشور، حالت، تعداد worker، timeout)
3. اسکن و تأیید سرورهای DNS با اتصال واقعی تونل
4. انتخاب سریع‌ترین سرور تأیید شده و شروع slipstream-client
5. تنظیم بررسی سلامت هر ساعت

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
- آیا سرور در حال اجراست؟
  - باینری: `systemctl status slipstream-server`
  - داکر: `docker ps | grep slipstream`
- آیا پورت 53 روی سرور باز است؟
- بررسی لاگ سرور:
  - باینری: `journalctl -u slipstream-server -f`
  - داکر: `docker logs slipstream-server -f`

**کلاینت: "Cannot download"**
- شبکه بسته است
- از حالت آفلاین با `--dnscan` و `--slipstream` استفاده کنید
- باینری‌ها را دانلود کنید:
  - https://github.com/nightowlnerd/dnscan/releases
  - https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases

</div>
