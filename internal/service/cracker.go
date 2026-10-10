package service

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"brute/internal/domain"
)

// crackerService — оркестратор подбора по схеме fan-out через batch-канал.
type crackerService struct {
	source domain.CandidateSource
	hasher domain.Hasher
}

// NewCracker собирает оркестратор из источника кандидатов и проверяющего Hasher.
func NewCracker(source domain.CandidateSource, hasher domain.Hasher) domain.Cracker {
	return &crackerService{source: source, hasher: hasher}
}

// Crack запускает пул воркеров:
//  1. Генератор (CandidateSource) кладёт в канал пачки кандидатов.
//  2. N воркеров читают пачки и проверяют каждого кандидата через Hasher.Match.
//  3. Первый Match==true отменяет общий ctx — генератор и воркеры завершаются.
//  4. Отмена входящего ctx (например, SIGINT) тоже корректно всё останавливает.
//  5. Счётчик попыток — atomic.Uint64.
func (c *crackerService) Crack(ctx context.Context, req domain.Request) (domain.Result, error) {
	start := time.Now()

	// Общий контекст: отменяется при нахождении пароля либо извне (SIGINT).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	batches, err := c.source.Batches(ctx)
	if err != nil {
		return domain.Result{}, err
	}

	workers := req.Threads
	if workers < 1 {
		workers = 1
	}

	var (
		attempts atomic.Uint64
		found    atomic.Bool
		password string
		once     sync.Once
		wg       sync.WaitGroup
	)

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case batch, ok := <-batches:
					if !ok {
						return // источник исчерпан
					}
					for _, candidate := range batch {
						if found.Load() {
							return // пароль уже найден другим воркером
						}
						attempts.Add(1)
						if c.hasher.Match(candidate) {
							once.Do(func() {
								password = candidate
								found.Store(true)
								cancel() // остановить генератор и остальных воркеров
							})
							return
						}
					}
				}
			}
		}()
	}

	wg.Wait()

	return domain.Result{
		Password: password,
		Found:    found.Load(),
		Attempts: attempts.Load(),
		Duration: time.Since(start),
	}, nil
}
