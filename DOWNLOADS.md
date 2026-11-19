# Скачать silikbox для Android

## silikbox 1.0.0 · ARM64

### [Скачать подписанный APK для Android](https://github.com/silikonoff/silikbox/releases/download/v1.0.0/silikbox-1.0.0-arm64-v8a.apk)

| Файл | Назначение |
| --- | --- |
| [silikbox-1.0.0-arm64-v8a.apk](https://github.com/silikonoff/silikbox/releases/download/v1.0.0/silikbox-1.0.0-arm64-v8a.apk) | Установка и обновление |
| [silikbox-1.0.0-SHA256.txt](https://github.com/silikonoff/silikbox/releases/download/v1.0.0/silikbox-1.0.0-SHA256.txt) | Контрольная сумма APK |
| [silikbox-1.0.0-validation.json](https://github.com/silikonoff/silikbox/releases/download/v1.0.0/silikbox-1.0.0-validation.json) | Результаты проверки APK |

[Описание выпуска](https://github.com/silikonoff/silikbox/releases/tag/v1.0.0) · [Все выпуски](https://github.com/silikonoff/silikbox/releases) · [Возможности приложения](README.md)

### Что нового

- VLESS **XHTTP / SplitHTTP** через встроенный Xray-core 26.11.9.
- Импорт VLESS XHTTP-ссылок из 3x-ui с параметрами Host, пути и REALITY.
- Реальный трафик через **VLESS + XHTTP + REALITY на публичном 443** подтверждён на физическом Infinix с Android 11. Тест VPN загрузил 1 МиБ по HTTPS.
- Текущая DNS-цепочка для адреса VPN-сервера — Google DoH → обычный DNS Cloudflare → системный DNS Android. [Подробнее о DNS](docs/DNS.md)

### Установка и обновление

1. Скачайте APK на телефон с **ARM64 / arm64-v8a**. Минимальный API — Android 5.0 / API 21.
2. Откройте файл. Если Android запросит разрешение для выбранного источника, разрешите установку.
3. Обновляйте silikbox установкой **поверх прежней сборки**, чтобы сохранить профили и настройки. Пакет и сертификат подписи совпадают. Код новой версии — **280**.
4. Импортируйте профиль или подписку. Выберите профиль, запустите подключение и подтвердите создание VPN.

Оригинальный NekoBox можно держать рядом с silikbox. Для подключения выберите один VPN-клиент.
