// Package domain содержит общие типы и контракты (интерфейсы), через которые
// общаются слои handler → service → repository. Это единственное место, от
// которого зависят все слои; сами слои друг на друга напрямую не ссылаются.
package domain

import (
	"context"
	"time"
)

// Algo — поддерживаемый алгоритм хэширования.
type Algo string

const (
	AlgoSHA1   Algo = "sha1"
	AlgoMD5    Algo = "md5"
	AlgoBcrypt Algo = "bcrypt"
	AlgoArgon2 Algo = "argon2"
)

// Request — входные параметры одной задачи подбора.
type Request struct {
	Hash    string
	Algo    Algo
	Threads int

	// Параметры bruteforce (sha1/md5).
	Charset string
	MinLen  int
	MaxLen  int

	// Параметры dictionary (bcrypt/argon2).
	Wordlist string
}

// Result — итог подбора.
type Result struct {
	Password string
	Found    bool
	Attempts uint64
	Duration time.Duration
}

// CandidateSource — источник кандидатов в пароли (repository).
type CandidateSource interface {
	// Batches отдаёт канал пачек кандидатов. Канал закрывается при исчерпании
	// пространства перебора / файла словаря либо при отмене ctx. Возвращаемая
	// ошибка — только фатальная (например, не открылся файл словаря).
	Batches(ctx context.Context) (<-chan []string, error)
}

// Hasher — проверка одного кандидата против целевого хэша (service).
type Hasher interface {
	// Validate проверяет, что целевой хэш корректен для данного алгоритма.
	Validate() error
	// Match возвращает true, если candidate соответствует целевому хэшу.
	Match(candidate string) bool
}

// Cracker — оркестратор подбора (service).
type Cracker interface {
	Crack(ctx context.Context, req Request) (Result, error)
}
