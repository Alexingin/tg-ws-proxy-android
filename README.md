<div align="center">

# TG WS Proxy Android

**Локальный MTProto-прокси для Telegram на Android, который не засыпает в фоне**

<br>

<img src="https://img.shields.io/badge/Android-5.0+-3DDC84?style=for-the-badge&logo=android&logoColor=white" alt="Android">
<img src="https://img.shields.io/badge/Rust-движок-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
<img src="https://img.shields.io/badge/Kotlin-Compose-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white" alt="Kotlin">
<a href="https://github.com/Alexingin/tg-ws-proxy-android/actions">
  <img src="https://img.shields.io/github/actions/workflow/status/Alexingin/tg-ws-proxy-android/build-apk.yml?style=for-the-badge&logo=github&label=сборка" alt="Build">
</a>

</div>

<br>

Это продолжение проекта [amurcanov/tg-ws-proxy-android](https://github.com/amurcanov/tg-ws-proxy-android) — Android-порта [TgWsProxy от Flowseal](https://github.com/Flowseal/tg-ws-proxy). Оригинальный форк перестал обновляться, а в нём остался неприятный баг: прокси отваливался каждые 10–15 минут и оживал только после ручного перезапуска.

Цель этого репозитория — исправить накопившиеся ошибки, подтягивать изменения из оригинального TgWsProxy и поддерживать приложение дальше.

---

## Что это и зачем

Приложение поднимает на телефоне локальный MTProto-прокси. Telegram подключается к нему, а прокси уже сам доставляет трафик до серверов Telegram через WebSocket (TLS) — напрямую или через Cloudflare. Никаких сторонних серверов и VPN: всё работает на самом телефоне.

```text
Telegram → 127.0.0.1:1443 (MTProto) → TG WS Proxy → WSS напрямую / через Cloudflare → дата-центр Telegram
```

Движок написан на **Rust**, интерфейс — на **Kotlin + Jetpack Compose** (Material 3).

---

## Что изменено в этом форке

### 1.2.3-stable — стабильность в фоне

Главное: прокси больше не «засыпает».

- **Не блокирует дата-центр на час из-за одного сбоя.** Раньше один таймаут подключения (погас экран, переключился Wi-Fi ↔ LTE, связь моргнула) отправлял DC в чёрный список на 3600 секунд. Теперь — на 30 секунд, а блокировка «все домены ответили 302» живёт 10 минут вместо «до перезапуска».
- **Живой пул соединений.** Пул заготовленных соединений перестал умирать, когда все соединения протухали одновременно: обслуживающая задача теперь работает постоянно и сама дотягивает пул (по образцу актуального TgWsProxy).
- **Реакция на смену сети и пробуждение.** При переключении сети или включении экрана после сна прокси сбрасывает накопленные блокировки и старые соединения — по сути мягкий перезапуск без обрыва текущих соединений Telegram.
- **Сторожок.** Если локальный порт перестаёт отвечать, прокси перезапускается сам.
- **Восстановление слушающего сокета** вместо холостого цикла при ошибках.
- **Сборка APK через GitHub Actions** — больше не нужен Android Studio, чтобы собрать приложение.

---

## Установка

1. Скачайте APK со [страницы релизов](https://github.com/Alexingin/tg-ws-proxy-android/releases) или из последней успешной сборки во вкладке [Actions](https://github.com/Alexingin/tg-ws-proxy-android/actions) (раздел *Artifacts*).
   - `arm64` — для любого современного телефона;
   - `universal` — если не уверены или устройство старое (32-бит).
2. **Если у вас стоит версия от amurcanov — сначала удалите её.** Сборки подписаны другим ключом, и Android не даст установить поверх.
3. Откройте приложение и нажмите **«Запустить прокси»** — появится уведомление о работе в фоне.
4. Нажмите **«Применить в Telegram»** и подтвердите подключение в клиенте.

Поддерживаются официальный Telegram и большинство форков: AyuGram, exteraGram, Plus Messenger, Nekogram, Nagram, Cherrygram, Telegraph и другие.

> [!TIP]
> Для надёжной работы в фоне отключите для приложения оптимизацию батареи и разрешите автозапуск (на Xiaomi, Huawei, Samsung и т. п. это отдельные пункты в настройках).

---

## Сборка из исходников

**Через GitHub Actions (проще всего).** Сделайте форк, включите Actions и запустите workflow **Build APK** — через 10–15 минут готовые APK появятся в *Artifacts*. Каждый пуш собирается автоматически.

**Локально на Windows.** Нужны Rust, Android Studio (SDK + NDK):

1. `build_so.bat` — собирает нативную библиотеку движка для arm64-v8a и armeabi-v7a.
2. `build_apk.bat` — собирает APK.

---

## Планы

- [ ] Перенести актуальные изменения из TgWsProxy: переработанный пул, backoff для TCP-fallback, мультиплексирование медиа через Cloudflare.
- [ ] Переключить встроенную проверку обновлений на релизы этого репозитория.
- [ ] Регулярные релизы с подписанными APK.

Есть идея или нашли баг — открывайте [issue](https://github.com/Alexingin/tg-ws-proxy-android/issues).

---

## Сообщить о проблеме

Если прокси отваливается или работает странно:

1. Откройте в приложении вкладку логов сразу после сбоя.
2. Нажмите **«Собрать отчёт»**.
3. Создайте [issue](https://github.com/Alexingin/tg-ws-proxy-android/issues): модель телефона, версия Android, тип сети (Wi-Fi / мобильная) и отчёт.

Единичные ошибки в логах при нормально работающем Telegram — это нормально, на них можно не обращать внимания.

---

## Благодарности

- [Flowseal](https://github.com/Flowseal) — автор оригинального [TgWsProxy](https://github.com/Flowseal/tg-ws-proxy);
- [amurcanov](https://github.com/amurcanov) и контрибьюторы — Android-порт, на котором основан этот проект.

## Лицензия

Проект распространяется под лицензией **GPLv3**, как и Android-порт, на котором он основан. Оригинальный код TgWsProxy от Flowseal доступен под лицензией **MIT**.
