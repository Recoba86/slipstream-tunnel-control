<div dir="rtl">

# slipstream-tunnel

[English](README.md) | **فارسی**

راه‌اندازی تونل DNS با slipstream و اسکن خودکار سرورهای DNS توسط dnscan.

نصاب در صورت امکان وابستگی‌های لازم (مثل `sshpass`، `openssh-client` و ابزارهای DNS) را به‌صورت خودکار نصب می‌کند.

## شروع سریع

### سرور (خارج از ایران)

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/Recoba86/slipstream-tunnel-control/main/install.sh | sudo bash -s -- server
```

<div dir="rtl">

دستورات را دنبال کنید تا DNS کلودفلر را تنظیم کنید.

### کلاینت (داخل ایران)

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/Recoba86/slipstream-tunnel-control/main/install.sh | sudo bash -s -- client
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
- در صورت استفاده از احراز هویت SSH: نصب بودن OpenSSH Server (`sshd`)

### کلاینت
- ماشین لینوکس با دسترسی root
- در صورت استفاده از auth کلاینت: نصب بودن `ssh` و `sshpass`
- برای حالت آفلاین:
  - [dnscan releases](https://github.com/nightowlnerd/dnscan/releases)
  - [slipstream releases](https://github.com/nightowlnerd/slipstream-rust/releases)

از [فورک slipstream-rust](https://github.com/nightowlnerd/slipstream-rust) با رفع باگ‌های مصرف CPU و قطع اتصال استفاده می‌کند. ریپوی اصلی دیگر فعال نیست.

هسته‌های قابل استفاده:
- `dnstm` (پیش‌فرض جدید، دانلود از [net2share/slipstream-rust-build](https://github.com/net2share/slipstream-rust-build))
- `nightowl` (نسخه پایدار قدیمی)
- `plus` (سریع‌تر، آزمایشی)

## دستورات

</div>

```bash
slipstream-tunnel server    # راه‌اندازی سرور
slipstream-tunnel client    # راه‌اندازی کلاینت
slipstream-tunnel edit      # ویرایش تنظیمات ذخیره‌شده (دامنه/پورت/...)
slipstream-tunnel start     # شروع سرویس تونل (بر اساس mode فعلی)
slipstream-tunnel stop      # توقف سرویس تونل (بر اساس mode فعلی)
slipstream-tunnel restart   # ری‌استارت سرویس تونل (بر اساس mode فعلی)
slipstream-tunnel status    # نمایش وضعیت
slipstream-tunnel logs      # مشاهده لاگ (با -f برای دنبال کردن)
slipstream-tunnel health    # بررسی DNS و تعویض اگر کند باشد
slipstream-tunnel watchdog  # بررسی فوری runtime و self-heal (کلاینت)
slipstream-tunnel rescan    # اسکن دستی DNS و تعویض به بهترین
slipstream-tunnel dashboard # داشبورد کوچک کلاینت
slipstream-tunnel servers   # نمایش کامل DNSهای تاییدشده با ping و latency
slipstream-tunnel instance-add <name> # افزودن کلاینت اضافه روی همین ماشین
slipstream-tunnel instance-list # لیست کلاینت‌های اضافه
slipstream-tunnel instance-status <name> # وضعیت یک کلاینت اضافه
slipstream-tunnel instance-start <name> # شروع یک کلاینت اضافه
slipstream-tunnel instance-stop <name> # توقف یک کلاینت اضافه
slipstream-tunnel instance-restart <name> # ری‌استارت یک کلاینت اضافه
slipstream-tunnel instance-logs <name> [-f] # لاگ یک کلاینت اضافه
slipstream-tunnel instance-del <name> # حذف یک کلاینت اضافه
slipstream-tunnel menu      # منوی مانیتورینگ دستی
sst                         # دستور کوتاه برای باز کردن منوی مانیتورینگ
slipstream-tunnel speed-profile [fast|secure|status] # تغییر/نمایش پروفایل سرعت
slipstream-tunnel core-switch [dnstm|nightowl|plus] # تعویض هسته بعد از نصب (بدون uninstall)
slipstream-tunnel dnstm <subcommands...> # پاس‌دادن مستقیم به مدیر native dnstm (سرور+dnstm)
slipstream-tunnel auth-setup # فعال‌سازی/به‌روزرسانی لایه احراز هویت SSH (سرور)
slipstream-tunnel auth-disable # غیرفعال‌سازی لایه احراز هویت SSH (سرور)
slipstream-tunnel auth-client-enable # فعال‌سازی auth SSH در کلاینت
slipstream-tunnel auth-client-disable # غیرفعال‌سازی auth SSH در کلاینت
slipstream-tunnel auth-add   # ساخت کاربر SSH برای تونل
slipstream-tunnel auth-passwd # تغییر رمز کاربر SSH تونل
slipstream-tunnel auth-del   # حذف کاربر SSH تونل
slipstream-tunnel auth-list  # لیست کاربران SSH تونل
slipstream-tunnel uninstall # حذف کامل
slipstream-tunnel remove    # حذف همه چیز
```

داخل `menu` گزینه‌ها در ساب‌منوهای مرتب (مانیتورینگ، سرویس، auth/profile) گروه‌بندی شده‌اند.
وقتی هسته سرور `dnstm` باشد، ساب‌منوی native برای مدیریت router/tunnel/backend/ssh-users/update اضافه می‌شود.
در منوی کلاینت هم ساب‌منوی DNSTM برای مدیریت transport/profile هر تونل (`slipstream`/`dnstt`) اضافه شده است.

## حالت Multi-Instance کلاینت

می‌توانید روی یک ماشین چند کلاینت همزمان بالا بیاورید (با پورت‌های محلی متفاوت)، مثل:

- `7001` -> Finland
- `7002` -> Dubai
- `7003` -> Netherlands

مثال:

```bash
slipstream-tunnel instance-add finland
slipstream-tunnel instance-add dubai
slipstream-tunnel instance-list
slipstream-tunnel instance-status finland
```

نکته: کلاینت‌های اضافه از هر دو transport یعنی `slipstream` و `dnstt` پشتیبانی می‌کنند (SSH auth overlay همچنان خاموش است).

نکته: روی هسته `dnstm`، دستورات قدیمی SSH auth overlay غیرفعال هستند و باید از مکانیزم native همان هسته برای auth/backend استفاده شود.

## مدیریت Native با dnstm

- روی هسته `dnstm` در حالت سرور، اسکریپت الان مدیر native `dnstm` را نصب/استفاده می‌کند.
- در نصب اولیه، استک native به‌صورت خودکار ساخته می‌شود (install + backend + tunnel اولیه).
- روی کلاینت با هسته `dnstm`، برای هر تونل/اینستنس می‌توانید transport را بین `slipstream` و `dnstt` انتخاب کنید.
- مدیریت native هم از داخل منو ممکن است (`Server Main Menu -> Native dnstm manager`) و هم با دستور مستقیم:

```bash
slipstream-tunnel dnstm router status
slipstream-tunnel dnstm tunnel list
slipstream-tunnel dnstm backend list
slipstream-tunnel dnstm ssh-users
```

<div dir="rtl">

## گزینه‌ها

| گزینه | توضیح |
|-------|-------|
| `--domain` | دامنه تونل (مثلاً t.example.com) |
| `--port` | سرور: پورت هدف / کلاینت: پورت شنود |
| `--core` | منبع هسته: `dnstm` (پیش‌فرض)، `nightowl` یا `plus` |
| `--dns-file` | لیست سرورهای DNS (بدون اسکن subnet) |
| `--dnscan` | مسیر فایل dnscan (حالت آفلاین) |
| `--slipstream` | مسیر باینری slipstream (حالت آفلاین) |
| `--transport` | کلاینت: transport برابر `slipstream` (پیش‌فرض) یا `dnstt` (در هسته dnstm) |
| `--dnstt-pubkey` | کلاینت با transport=`dnstt`: کلید عمومی DNSTT (۶۴ کاراکتر hex) |
| `--dnstt-client` | کلاینت با transport=`dnstt`: مسیر باینری محلی `dnstt-client` |
| `--slipstream-cert` | کلاینت با transport=`slipstream`: مسیر اختیاری cert برای pinning |
| `--dnstm-bin` | سرور: مسیر باینری محلی dnstm (حالت آفلاین) |
| `--dnstm-transport` | سرور (هسته dnstm): ترنسپورت اولیه `slipstream` یا `dnstt` |
| `--dnstm-backend` | سرور (هسته dnstm): بک‌اند اولیه `custom`، `socks`، `ssh` یا `shadowsocks` |
| `--dnstm-backend-tag` | سرور (هسته dnstm): تگ بک‌اند اولیه |
| `--dnstm-tunnel-tag` | سرور (هسته dnstm): تگ تونل اولیه |
| `--dnstm-mode` | سرور (هسته dnstm): مود native router (`single` یا `multi`) |
| `--dnstm-ss-password` | سرور (هسته dnstm): رمز اولیه shadowsocks (اختیاری) |
| `--dnstm-ss-method` | سرور (هسته dnstm): متد shadowsocks (پیش‌فرض `aes-256-gcm`) |
| `--manage-resolver` | اجازه تغییر resolver روی سرور |
| `--ssh-auth` | سرور: فعال‌سازی احراز هویت نام‌کاربری/رمز عبور SSH |
| `--ssh-backend-port` | سرور: پورت SSH پشت slipstream در حالت auth |
| `--ssh-auth-client` | کلاینت: فعال‌سازی حالت احراز هویت SSH |
| `--ssh-user` | کلاینت: نام کاربری SSH برای auth |
| `--ssh-pass` | کلاینت: رمز SSH برای auth |

## نحوه کار

برای A/B تست در برنچ/محیط جدا:

```bash
slipstream-tunnel server --core dnstm --domain t.example.com
slipstream-tunnel client --core dnstm --domain t.example.com
```

### مهاجرت سرور/کلاینت قدیمی به هسته پیش‌فرض جدید

اگر از اسکریپت/هسته قبلی استفاده می‌کنید، درجا آپدیت و سوییچ کنید:

```bash
curl -fL https://raw.githubusercontent.com/Recoba86/slipstream-tunnel-control/main/install.sh -o /usr/local/bin/slipstream-tunnel
chmod +x /usr/local/bin/slipstream-tunnel
hash -r
slipstream-tunnel core-switch dnstm
```

این مراحل را هم روی سرور و هم روی کلاینت اجرا کنید.

### راه‌اندازی سرور

1. راهنمای تنظیم DNS کلودفلر (رکوردهای A و NS)
2. تأیید DNS با `dig`
3. تشخیص خودکار تداخل پورت 53 و تلاش برای رفع امن آن
4. اگر هسته `dnstm` باشد: نصب مدیر native `dnstm` + ساخت backend/tunnel اولیه + استارت router
5. اگر هسته `nightowl/plus` باشد: تولید گواهی SSL + نصب `slipstream-server` + استارت سرویس
6. اختیاری (فقط هسته‌های legacy): فعال‌سازی لایه احراز هویت SSH و ساخت کاربر تونل

### راه‌اندازی کلاینت

1. در هسته `dnstm`، انتخاب transport (`slipstream` یا `dnstt`)
2. دانلود باینری‌های لازم (slipstream client و/یا dnstt-client) با کش
3. درخواست پورت تونل کلاینت (پیش‌فرض: 7000)
4. برای `slipstream`: اسکن dnscan با verify؛ برای `dnstt`: ساخت لیست resolverهای قابل دسترس
5. انتخاب سریع‌ترین resolver و اجرای سرویس کلاینت با transport انتخابی
6. اختیاری (فقط هسته‌های legacy): دریافت نام‌کاربری/رمز و فعال‌سازی لایه SSH
7. تنظیم Health (هر ۵ دقیقه) + Runtime Watchdog (هر ۳۰ ثانیه) و باز کردن منوی مانیتورینگ

### Health و Recovery

- Health timer هر ۵ دقیقه اجرا می‌شود
- Runtime watchdog هر ۳۰ ثانیه اجرا می‌شود
- تأخیر سرور DNS فعلی را تست می‌کند
- اگر تأخیر > 1000ms باشد، به سرور بهتر تغییر می‌دهد
- اگر خطاهای runtime یا قطع listener دیده شود، کلاینت به‌صورت خودکار restart می‌شود
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

## پروفایل سرعت

- `slipstream-tunnel speed-profile secure`: لایه SSH روشن (امن‌تر، کمی کندتر)
- `slipstream-tunnel speed-profile fast`: لایه SSH خاموش (سریع‌تر)
- `slipstream-tunnel speed-profile status`: نمایش وضعیت پروفایل

برای تغییر جداگانه:
- سرور: `auth-setup` / `auth-disable`
- کلاینت: `auth-client-enable` / `auth-client-disable`

## بهینه‌سازی TCP (BBR)

اسکریپت در مراحل نصب و `edit` تلاش می‌کند BBR + fq را فعال کند (در صورت پشتیبانی کرنل).

بررسی وضعیت:

```bash
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
```

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
  - https://github.com/Fox-Fig/slipstream-rust-plus-deploy/releases
  - https://github.com/nightowlnerd/slipstream-rust/releases

</div>
