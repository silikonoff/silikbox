# Сборка silikbox

Набор для сборки XHTTP — Windows PowerShell, Python 3.11+, Git, Go 1.27.3, JDK 21,
Android SDK35, build-tools35.0.1, NDK28.2.13676358. Путь проекта без пробелов.
Gradle Wrapper использует Gradle 8.14.7, AGP 8.11.1 и Kotlin 2.2.21.
Room 2.7.2 работает с KSP2 и поддерживает минимальный API 21.
В PATH должны быть Python, Git, Go и Java. Ядро — закреплённый sing-box с нашим
патчем; libneko/gomobile уже находятся в `third_party`.

```powershell
python tools/prepare_assets.py
./buildScript/windows/Build-Libcore.ps1 -SdkRoot C:/Android/sdk -JavaHome C:/Java/jdk-21
./gradlew.bat --no-daemon --max-workers=2 app:testOssDebugUnitTest app:assembleOssRelease
```

Имя/версия/пакет задаются в `silikbox.properties`.
В локальном `local.properties` задаётся `sdk.dir`; файл не отправляется в Git.
По умолчанию ядро ARM64: распространять только APK `arm64-v8a`.
`-UseExistingEnvironment` разрешает использовать настроенные GOPATH/GOCACHE/
GOTMPDIR; иначе сборщик создаёт их в `.build/windows`.

## Подпись и обновления

У установочного APK сохраняется идентификатор `io.github.silikonoff.nekobox.debug`
для обновления прежних сборок. Сборка `ossRelease` отключает отладку приложения.

Подписывайте ARM64 APK локально прежним ключом владельца. Для обновления
поверх silikbox alpha4 нужен тот же пакет, сертификат и versionCode выше 275.
У silikbox 1.0.0 versionCode 280, у 1.1 — 285. Храните рабочий keystore вне репозитория.

GitHub Actions проверяет тесты и создаёт **неподписанный APK**. Подписанные
установочные APK доступны в [GitHub Releases](https://github.com/silikonoff/silikbox/releases).

## Проверки

```powershell
python tools/check_repository.py
go -C libcore test -ldflags '-checklinkname=0' -tags with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api ./configcompat ./connectiontest ./bootstrapdns ./xhttp
./gradlew.bat app:testOssDebugUnitTest --tests '*XHttpImportTest'
$aapt2 = Join-Path $env:ANDROID_HOME 'build-tools/35.0.1/aapt2.exe'
python tools/verify_apk.py APK_PATH app/libs/libcore.aar report.json --runtime-label 1.14.4-silikbox.3 --aapt2 $aapt2
```

Также проверять `apksigner verify`, alignment16KiB, пакет и ярлык через
`aapt dump badging`. Сборка не заменяет запуск VPN: нужны импорт, реальные
DNS/HTTPS, перезапуск и сохранение профилей. Публичные отчёты не должны содержать
ключи, пользовательские UUID, частные адреса серверов, serial и сырые журналы.
Генератор JNI из `third_party/gomobile` собирается Go 1.25.5. Для сборки
без загрузки этой версии передайте путь к компилятору через `-GomobileGo`
в `Build-Libcore.ps1`.

XHTTP использует Xray-core 26.11.9 под MPL-2.0. Точный исходный код
закреплён в `libcore/go.mod`. [Xray-core 676eaf66](https://github.com/XTLS/Xray-core/tree/676eaf66f8f05d4d558ee7a74b4736623d3feeb9) · [Лицензия Xray-core](https://github.com/XTLS/Xray-core/blob/v26.11.9/LICENSE)
