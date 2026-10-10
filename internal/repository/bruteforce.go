package repository

import (
	"context"

	"brute/internal/domain"
)

// defaultBatchSize — размер пачки кандидатов. Отправлять в канал по одному
// кандидату — узкое место для быстрых sha1/md5 (миллионы хэшей/сек), поэтому
// кандидаты группируются в пачки, амортизируя оверхед канала.
const defaultBatchSize = 2048

// BruteForceSource перебирает все строки из charset длиной от minLen до maxLen.
type BruteForceSource struct {
	charset   []rune
	minLen    int
	maxLen    int
	batchSize int
}

// NewBruteForceSource создаёт источник полного перебора.
func NewBruteForceSource(charset string, minLen, maxLen int) *BruteForceSource {
	return &BruteForceSource{
		charset:   []rune(charset),
		minLen:    minLen,
		maxLen:    maxLen,
		batchSize: defaultBatchSize,
	}
}

// Batches генерирует кандидатов «одометром»: массив индексов по charset,
// который инкрементируется как разряды счётчика. Для производительности
// отмена ctx проверяется не на каждом кандидате, а на границе отправки пачки.
func (s *BruteForceSource) Batches(ctx context.Context) (<-chan []string, error) {
	out := make(chan []string, 8)

	go func() {
		defer close(out)

		if len(s.charset) == 0 {
			return
		}

		batch := make([]string, 0, s.batchSize)

		// send отправляет накопленную пачку; возвращает false при отмене ctx.
		send := func() bool {
			select {
			case out <- batch:
				batch = make([]string, 0, s.batchSize)
				return true
			case <-ctx.Done():
				return false
			}
		}

		buf := make([]rune, s.maxLen)

		for length := s.minLen; length <= s.maxLen; length++ {
			if length == 0 {
				// Единственный кандидат нулевой длины — пустая строка.
				batch = append(batch, "")
				continue
			}

			idx := make([]int, length)
			word := buf[:length]

			for {
				for i := 0; i < length; i++ {
					word[i] = s.charset[idx[i]]
				}
				batch = append(batch, string(word))

				if len(batch) >= s.batchSize {
					if !send() {
						return
					}
				}

				// Инкремент одометра: младший разряд — последний символ.
				pos := length - 1
				for pos >= 0 {
					idx[pos]++
					if idx[pos] < len(s.charset) {
						break
					}
					idx[pos] = 0
					pos--
				}
				if pos < 0 {
					break // пространство данной длины исчерпано
				}
			}
		}

		if len(batch) > 0 {
			send()
		}
	}()

	return out, nil
}

var _ domain.CandidateSource = (*BruteForceSource)(nil)
