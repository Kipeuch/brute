# Password Cracker (SDLC Lab 3)

Учебное средство подбора пароля по хэшу на Go для сравнительного исследования
алгоритмов хэширования. Реализация по дизайн-спеке
[`docs/superpowers/specs/2026-10-09-password-cracker-design.md`](docs/superpowers/specs/2026-10-09-password-cracker-design.md).

- **SHA-1, MD5** — полный перебор (bruteforce) по настраиваемому charset.
- **bcrypt, Argon2id** — перебор по словарю (dictionary attack): эти алгоритмы
  намеренно медленные и memory-hard, перебор charset бессмыслен.

## Архитектура

Строгая слоёная архитектура, связи только через интерфейсы (`internal/domain`):

```
cmd/brute/main.go        entrypoint -> handler.Execute()
internal/
  handler/               cobra-команда: флаги, валидация, вывод
  service/               Cracker (пул воркеров) + Hasher (4 реализации)
  repository/            CandidateSource: BruteForceSource, WordlistSource
  domain/                Request, Result, интерфейсы
wordlists/               словари (rockyou.txt не в git)
```

## Сборка

```bash
go build -o bin/brute ./cmd/brute
```

## Использование

```
brute <hash> --algo sha1|md5|bcrypt|argon2 [флаги]
```

Флаги:

| Флаг | Назначение | Дефолт |
|---|---|---|
| `--algo` | алгоритм: `sha1\|md5\|bcrypt\|argon2` (обязательный) | — |
| `--threads` | число воркеров | `runtime.NumCPU()` |
| `--charset` | пресет `digits\|lower\|upper\|alnum\|all` или произвольная строка (только bruteforce) | `lower+digits` |
| `--min-len` | минимальная длина пароля (только bruteforce) | `1` |
| `--max-len` | максимальная длина пароля (только bruteforce) | `6` |
| `--wordlist` | путь к словарю (только dictionary) | `wordlists/rockyou.txt` |

Вывод: найденный пароль (или `not found`), число попыток, время и скорость
(хэш/сек).

### Примеры

```bash
# SHA-1 полным перебором по цифрам
brute 7c4a8d09ca3762af61e59520943dc26494f8941b --algo sha1 --charset digits --max-len 6

# MD5 полным перебором
brute e10adc3949ba59abbe56e057f20f883e --algo md5 --charset lower+digits

# bcrypt по словарю
brute '$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi' \
  --algo bcrypt --wordlist wordlists/sample.txt

# Argon2id по словарю (осторожно с --threads, см. ниже)
brute '$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c' \
  --algo argon2 --wordlist wordlists/sample.txt --threads 2
```

`Ctrl-C` (SIGINT) корректно останавливает подбор.

## ⚠️ Память для Argon2id

С параметрами из ТЗ (`m=65536` → ~64 МБ) **каждая** проверка пароля требует
~64 МБ. При пуле воркеров пиковое потребление ≈ `--threads × 64 МБ`. По умолчанию
`--threads = runtime.NumCPU()`, поэтому на многоядерной машине это могут быть
гигабайты. Для argon2 задавайте `--threads` осознанно (например, `2`).

## Эталонные хэши из ТЗ

Параметры: bcrypt `cost=10`; Argon2id `v=19, m=65536, t=3, p=2, salt="saltsalt"`.
Таблица хэшей — в [дизайн-спеке](docs/superpowers/specs/2026-10-09-password-cracker-design.md).
Известный пароль для «лёгких» SHA-1/MD5 — `123456` (есть в `wordlists/sample.txt`).

## Словари

В репозитории лежит небольшой `wordlists/sample.txt` для демонстрации словарной
атаки. Полноценный `wordlists/rockyou.txt` (дефолтный путь) в git не хранится —
скачайте его отдельно и положите в `wordlists/`.

## Вне рамок

Установка/запуск hashcat/john, замеры на GPU, текст отчёта. Опциональная
оптимизация (партиционирование пространства перебора, GPU) — возможное развитие.
