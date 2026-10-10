package repository

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"brute/internal/domain"
)

// WordlistSource читает кандидатов построчно из файла-словаря.
type WordlistSource struct {
	path      string
	batchSize int
}

// NewWordlistSource создаёт источник словарной атаки.
func NewWordlistSource(path string) *WordlistSource {
	return &WordlistSource{path: path, batchSize: defaultBatchSize}
}

// Batches открывает файл словаря и построчно отдаёт кандидатов пачками.
// Если файл не открылся — это фатальная ошибка, возвращается сразу. Пустые
// строки пропускаются. Канал закрывается по EOF или по отмене ctx.
func (s *WordlistSource) Batches(ctx context.Context) (<-chan []string, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть словарь %q: %w", s.path, err)
	}

	out := make(chan []string, 8)

	go func() {
		defer close(out)
		defer f.Close()

		sc := bufio.NewScanner(f)
		// Увеличенный буфер: отдельные строки в словарях бывают длинными.
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		batch := make([]string, 0, s.batchSize)

		send := func() bool {
			select {
			case out <- batch:
				batch = make([]string, 0, s.batchSize)
				return true
			case <-ctx.Done():
				return false
			}
		}

		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				continue
			}
			batch = append(batch, line)
			if len(batch) >= s.batchSize {
				if !send() {
					return
				}
			}
		}

		if len(batch) > 0 {
			send()
		}
	}()

	return out, nil
}

var _ domain.CandidateSource = (*WordlistSource)(nil)
