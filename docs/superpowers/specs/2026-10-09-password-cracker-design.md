# Дизайн: Password Cracker (SDLC Lab 3)

Дата: 2026-10-09
Статус: утверждён (дизайн), ожидает вычитки спеки

## 1. Цель и контекст

Учебное средство подбора пароля на Go для сравнительного исследования
алгоритмов хэширования (SDLC Lab 3). Инструмент принимает на вход хэш и
восстанавливает исходный пароль:

- **SHA-1, MD5** — полным перебором (bruteforce) по настраиваемому charset.
- **bcrypt, Argon2id** — перебором по словарю (dictionary attack), т.к. эти
  алгоритмы намеренно медленные и memory-hard, перебор charset бессмыслен.

Результат работы (время/скорость подбора) используется студентом для отчёта
и сравнения с hashcat/john. Установка и запуск hashcat/john и сам текст
отчёта — вне рамок кода.

### Эталонные хэши из ТЗ (для тестов/демо)

Параметры: bcrypt cost=10; Argon2id v=19, m=65536, t=3, p=2, salt="saltsalt".

| Алг | лёгкий | средний | сложный | очень сложный |
|---|---|---|---|---|
| SHA-1 | 7c4a8d09ca3762af61e59520943dc26494f8941b | d0be2dc421be4fcd0172e5afceea3970e2f3d940 | 666846867fc5e0a46a7afc53eb8060967862f333 | 6e157c5da4410b7e9de85f5c93026b9176e69064 |
| MD5 | e10adc3949ba59abbe56e057f20f883e | 1f3870be274f6c49b3e31a0c6728957f | 77892341aa9dc66e97f5c248782b5d92 | 686e697538050e4664636337cc3b834f |
| bcrypt | $2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi | $2a$10$26GB/T2/6aTsMkTjCgqm/.JP8SUjr32Bhfn9m9smtDiIwM4QIt2ze | $2a$10$Q9M0vLLrE4/nu/9JEMXFTewB3Yr9uMdIEZ1Sgdk1NQTjHwLN0asfi | $2a$10$yZBadi8Szw0nItV2g96P6eqctI2kbG/.mb0uD/ID9tlof0zpJLLL2 |
| Argon2id | $argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c | $argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$HYQwRUw9VcfkvqkUQ5ppyYPom6f/ro3ZCXYznhrYZw4 | $argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$9asGA7Xv3vQBz7Yyh4/Ntw0GQgOg8R6OWolOfRETrEg | $argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$+smq45/czydGj0lYNdZVXF++FOXJwrkXt6VUIcEauvo |

Известные пароли (для unit-тестов "лёгких"): SHA-1/MD5 лёгкий = `123456`.

## 2. CLI (spf13/cobra)

Одна команда с положительным аргументом-хэшем и флагом алгоритма:

```
cracker brute <hash> --algo sha1|md5|bcrypt|argon2 [флаги]
```

Флаги:
- `--algo`   (обяз.) sha1|md5|bcrypt|argon2
- `--threads` число воркеров (дефолт runtime.NumCPU())
- bruteforce (sha1/md5): `--charset` (пресеты digits|lower|upper|alnum|all или
  произвольная строка; дефолт `lower+digits`), `--min-len` (дефолт 1),
  `--max-len` (дефолт 6)
- dictionary (bcrypt/argon2): `--wordlist` (путь; дефолт `wordlists/rockyou.txt`)

Вывод: найденный пароль или `not found`, число попыток, время, скорость (хэш/сек).

## 3. Архитектура (слоёная, связи только через интерфейсы)

```
cmd/cracker/main.go        entrypoint -> handler.Execute()
internal/
  handler/                 cobra-команда: парсинг флагов, валидация, вывод
  service/                 Cracker (worker pool) + Hasher (4 реализации)
  repository/              CandidateSource: BruteForceSource, WordlistSource
  domain/                  Request, Result, общие интерфейсы
mocks/                     gomock-моки
wordlists/rockyou.txt      словарь (НЕ в git)
```

Правило слоёв: Handler → Service → Repository, без перепрыгивания.

## 4. Контракты (интерфейсы)

```go
// domain
type Request struct {
    Hash    string
    Algo    Algo            // sha1|md5|bcrypt|argon2
    Threads int
    // bruteforce
    Charset string
    MinLen  int
    MaxLen  int
    // dictionary
    Wordlist string
}
type Result struct {
    Password string
    Found    bool
    Attempts uint64
    Duration time.Duration
}

// repository — источник кандидатов
type CandidateSource interface {
    // Batches отдаёт канал пачек кандидатов; закрывается при исчерпании
    // пространства/файла или при отмене ctx. Ошибка — только фатальная
    // (например, не открылся файл словаря).
    Batches(ctx context.Context) (<-chan []string, error)
}

// service — проверка одного кандидата против целевого хэша
type Hasher interface {
    Validate() error            // формат хэша корректен для этого алгоритма
    Match(candidate string) bool
}

// service — оркестратор
type Cracker interface {
    Crack(ctx context.Context, req domain.Request) (domain.Result, error)
}
```

## 5. Модель многопоточности (ключевое место, с комментариями в коде)

**Batch-канал (fan-out):**
1. Генератор-горутина (из `CandidateSource`) кладёт в буферизованный канал
   пачки `[]string` (~1–4k элементов).
2. N воркеров (`--threads`) читают пачки, для каждого кандидата вызывают
   `Hasher.Match`.
3. Первый `Match==true` → `cancel()` общего `context.Context`; генератор и
   воркеры завершаются, `errgroup`/`WaitGroup` их дожидается.
4. SIGINT (Ctrl-C) тоже вызывает `cancel()` — корректная остановка.
5. Счётчик попыток — `atomic.Uint64`.

Почему батчи: отправка в канал на *каждый* кандидат — узкое место для быстрых
sha1/md5 (миллионы хэшей/сек); пачки амортизируют оверхед канала и работают
единообразно для перебора и словаря.

Память: argon2 ест ~64 МБ на попытку → в README предупреждение про разумный
`--threads` (иначе NumCPU×64МБ).

## 6. Алгоритмы (service/hasher)

- **SHA-1 / MD5**: `crypto/sha1`, `crypto/md5`; hex-строка, сравнение без
  учёта регистра (`strings.EqualFold`). `Validate`: длина hex 40/32.
- **bcrypt**: `golang.org/x/crypto/bcrypt.CompareHashAndPassword` — соль и cost
  зашиты в хэш. `Validate`: префикс `$2a$`/`$2b$`/`$2y$`.
- **Argon2id**: вручную парсим PHC `$argon2id$v=19$m=..,t=..,p=..$b64salt$b64hash`
  (комментарий в коде), KDF `golang.org/x/crypto/argon2.IDKey(pw, salt, t, m, p,
  keyLen)`, сравнение `crypto/subtle.ConstantTimeCompare`. `Validate`: префикс
  `$argon2id$` и разбор параметров.

## 7. Обработка ошибок

- Неверный формат хэша под `--algo` → ошибка из `Validate` до старта пула.
- Нет/не читается файл словаря → фатальная ошибка из `CandidateSource.Batches`.
- Исчерпали пространство/словарь без совпадения → `Result{Found:false}` (это
  результат, не ошибка).

## 8. Тестирование (table-driven, testify, gomock)

- **service.Cracker**: gomock на `CandidateSource` и `Hasher` — проверяем:
  находит совпадение; останавливается на первом; корректно считает попытки;
  возвращает Found=false при исчерпании; реагирует на отмену ctx.
- **service.Hasher (реальные)**: известные векторы (лёгкие хэши из ТЗ),
  негативные кейсы, `Validate` на мусоре.
- **repository.BruteForceSource**: малый charset/длина → ожидаемая
  последовательность и полнота.
- **repository.WordlistSource**: временный файл, пустые строки, EOF, отмена.
- **handler**: парсинг флагов, маппинг algo→Hasher/Source, ошибки валидации.

После написания тестов — обязательно проверить, что компилируются и проходят.

## 9. Зависимости

`github.com/spf13/cobra`, `golang.org/x/crypto` (bcrypt, argon2),
`github.com/stretchr/testify`, `go.uber.org/mock` (gomock).

## 10. Вне рамок

Установка/запуск hashcat/john, замеры на GPU, текст отчёта. Опциональная
оптимизация из ТЗ (партиционирование пространства перебора вместо канала,
GPU) — возможное развитие, в базовую реализацию не входит.
```
