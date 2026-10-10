package service

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"brute/internal/domain"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// NewHasher возвращает Hasher под выбранный алгоритм. Сам хэш нормализуется
// (обрезаются пробелы); проверка корректности формата — в Hasher.Validate.
func NewHasher(algo domain.Algo, hash string) (domain.Hasher, error) {
	hash = strings.TrimSpace(hash)
	switch algo {
	case domain.AlgoSHA1:
		return &sha1Hasher{target: strings.ToLower(hash)}, nil
	case domain.AlgoMD5:
		return &md5Hasher{target: strings.ToLower(hash)}, nil
	case domain.AlgoBcrypt:
		return &bcryptHasher{target: hash}, nil
	case domain.AlgoArgon2:
		return &argon2Hasher{raw: hash}, nil
	default:
		return nil, fmt.Errorf("неизвестный алгоритм: %q", algo)
	}
}

// --- SHA-1 ---

type sha1Hasher struct {
	target string // hex в нижнем регистре
}

func (h *sha1Hasher) Validate() error {
	if len(h.target) != 40 {
		return fmt.Errorf("sha1-хэш должен содержать 40 hex-символов, получено %d", len(h.target))
	}
	if _, err := hex.DecodeString(h.target); err != nil {
		return fmt.Errorf("sha1-хэш не является корректным hex: %w", err)
	}
	return nil
}

func (h *sha1Hasher) Match(candidate string) bool {
	sum := sha1.Sum([]byte(candidate))
	// Кодируем в стек-буфер, чтобы не аллоцировать на каждом кандидате.
	var buf [40]byte
	hex.Encode(buf[:], sum[:])
	return string(buf[:]) == h.target
}

// --- MD5 ---

type md5Hasher struct {
	target string // hex в нижнем регистре
}

func (h *md5Hasher) Validate() error {
	if len(h.target) != 32 {
		return fmt.Errorf("md5-хэш должен содержать 32 hex-символа, получено %d", len(h.target))
	}
	if _, err := hex.DecodeString(h.target); err != nil {
		return fmt.Errorf("md5-хэш не является корректным hex: %w", err)
	}
	return nil
}

func (h *md5Hasher) Match(candidate string) bool {
	sum := md5.Sum([]byte(candidate))
	var buf [32]byte
	hex.Encode(buf[:], sum[:])
	return string(buf[:]) == h.target
}

// --- bcrypt ---

type bcryptHasher struct {
	target string
}

func (h *bcryptHasher) Validate() error {
	if !strings.HasPrefix(h.target, "$2a$") &&
		!strings.HasPrefix(h.target, "$2b$") &&
		!strings.HasPrefix(h.target, "$2y$") {
		return fmt.Errorf("bcrypt-хэш должен начинаться с $2a$, $2b$ или $2y$")
	}
	// bcrypt.Cost заодно проверяет структурную корректность хэша.
	if _, err := bcrypt.Cost([]byte(h.target)); err != nil {
		return fmt.Errorf("некорректный bcrypt-хэш: %w", err)
	}
	return nil
}

func (h *bcryptHasher) Match(candidate string) bool {
	// Соль и cost зашиты в самом хэше.
	return bcrypt.CompareHashAndPassword([]byte(h.target), []byte(candidate)) == nil
}

// --- Argon2id ---

type argon2Hasher struct {
	raw string

	// Параметры, разобранные из PHC-строки в Validate.
	salt    []byte
	hash    []byte
	timeC   uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

func (h *argon2Hasher) Validate() error {
	return h.parse()
}

// parse разбирает PHC-строку вида
// $argon2id$v=19$m=65536,t=3,p=2$<base64-соль>$<base64-хэш>
// (base64 — raw std, без паддинга), раскладывая её на параметры KDF.
func (h *argon2Hasher) parse() error {
	parts := strings.Split(h.raw, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", "<b64 соль>", "<b64 хэш>"]
	if len(parts) != 6 || parts[0] != "" {
		return fmt.Errorf("некорректный формат argon2 PHC-строки")
	}
	if parts[1] != "argon2id" {
		return fmt.Errorf("поддерживается только argon2id, получено %q", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return fmt.Errorf("не удалось разобрать версию argon2: %w", err)
	}
	if version != argon2.Version {
		return fmt.Errorf("неподдерживаемая версия argon2: %d (ожидается %d)", version, argon2.Version)
	}

	var m, t, p int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return fmt.Errorf("не удалось разобрать параметры argon2 (m,t,p): %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("не удалось декодировать соль argon2: %w", err)
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("не удалось декодировать хэш argon2: %w", err)
	}

	h.salt = salt
	h.hash = digest
	h.memory = uint32(m)
	h.timeC = uint32(t)
	h.threads = uint8(p)
	h.keyLen = uint32(len(digest))
	return nil
}

func (h *argon2Hasher) Match(candidate string) bool {
	if h.salt == nil {
		// Защита на случай вызова Match без предварительного Validate.
		if err := h.parse(); err != nil {
			return false
		}
	}
	got := argon2.IDKey([]byte(candidate), h.salt, h.timeC, h.memory, h.threads, h.keyLen)
	return subtle.ConstantTimeCompare(got, h.hash) == 1
}
