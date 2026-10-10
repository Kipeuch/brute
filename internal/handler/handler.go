// Package handler реализует CLI (cobra): парсит флаги, валидирует вход,
// собирает нужные реализации service/repository и печатает результат.
package handler

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"brute/internal/domain"
	"brute/internal/repository"
	"brute/internal/service"

	"github.com/spf13/cobra"
)

const defaultWordlist = "wordlists/rockyou.txt"

// Execute — точка входа CLI. Вызывается из cmd/brute/main.go.
func Execute() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

// newRootCommand собирает корневую команду: хэш передаётся позиционным
// аргументом (brute <hash> [флаги]), без подкоманд.
func newRootCommand() *cobra.Command {
	var (
		algo     string
		threads  int
		charset  string
		minLen   int
		maxLen   int
		wordlist string
	)

	cmd := &cobra.Command{
		Use:   "brute <hash>",
		Short: "Учебное средство подбора пароля по хэшу (SDLC Lab 3)",
		Long: "Подбирает пароль к заданному хэшу.\n\n" +
			"sha1/md5 — полный перебор по charset; bcrypt/argon2 — по словарю.",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if threads < 1 {
				threads = runtime.NumCPU()
			}
			req := domain.Request{
				Hash:     args[0],
				Algo:     domain.Algo(algo),
				Threads:  threads,
				Charset:  resolveCharset(charset),
				MinLen:   minLen,
				MaxLen:   maxLen,
				Wordlist: wordlist,
			}
			return run(cmd, req)
		},
	}

	cmd.Flags().StringVar(&algo, "algo", "", "алгоритм: sha1|md5|bcrypt|argon2 (обязательно)")
	cmd.Flags().IntVar(&threads, "threads", runtime.NumCPU(), "число воркеров")
	cmd.Flags().StringVar(&charset, "charset", "lower+digits",
		"пресет digits|lower|upper|alnum|all или произвольная строка (bruteforce)")
	cmd.Flags().IntVar(&minLen, "min-len", 1, "минимальная длина пароля (bruteforce)")
	cmd.Flags().IntVar(&maxLen, "max-len", 6, "максимальная длина пароля (bruteforce)")
	cmd.Flags().StringVar(&wordlist, "wordlist", defaultWordlist, "путь к словарю (dictionary)")
	_ = cmd.MarkFlagRequired("algo")

	return cmd
}

func run(cmd *cobra.Command, req domain.Request) error {
	// Hasher + валидация формата хэша — до старта пула воркеров.
	hasher, err := service.NewHasher(req.Algo, req.Hash)
	if err != nil {
		return err
	}
	if err := hasher.Validate(); err != nil {
		return fmt.Errorf("валидация хэша: %w", err)
	}

	source, mode, err := buildSource(req)
	if err != nil {
		return err
	}

	// SIGINT/SIGTERM → отмена контекста → корректная остановка подбора.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Алгоритм: %s | режим: %s | воркеров: %d\n", req.Algo, mode, req.Threads)

	res, err := service.NewCracker(source, hasher).Crack(ctx, req)
	if err != nil {
		return err
	}

	printResult(out, res)
	return nil
}

// buildSource выбирает источник кандидатов по алгоритму и валидирует его
// параметры. sha1/md5 → полный перебор, bcrypt/argon2 → словарь.
func buildSource(req domain.Request) (domain.CandidateSource, string, error) {
	switch req.Algo {
	case domain.AlgoSHA1, domain.AlgoMD5:
		if req.Charset == "" {
			return nil, "", fmt.Errorf("пустой charset для перебора")
		}
		if req.MinLen < 1 {
			return nil, "", fmt.Errorf("--min-len должен быть >= 1")
		}
		if req.MaxLen < req.MinLen {
			return nil, "", fmt.Errorf("--max-len (%d) меньше --min-len (%d)", req.MaxLen, req.MinLen)
		}
		return repository.NewBruteForceSource(req.Charset, req.MinLen, req.MaxLen), "bruteforce", nil
	case domain.AlgoBcrypt, domain.AlgoArgon2:
		if req.Wordlist == "" {
			return nil, "", fmt.Errorf("не задан путь к словарю (--wordlist)")
		}
		return repository.NewWordlistSource(req.Wordlist), "dictionary", nil
	default:
		return nil, "", fmt.Errorf("неизвестный алгоритм %q (ожидается sha1|md5|bcrypt|argon2)", req.Algo)
	}
}

func printResult(out io.Writer, res domain.Result) {
	rate := 0.0
	if s := res.Duration.Seconds(); s > 0 {
		rate = float64(res.Attempts) / s
	}
	if res.Found {
		fmt.Fprintf(out, "НАЙДЕН пароль: %q\n", res.Password)
	} else {
		fmt.Fprintln(out, "пароль не найден (not found)")
	}
	fmt.Fprintf(out, "попыток:  %d\n", res.Attempts)
	fmt.Fprintf(out, "время:    %s\n", res.Duration.Round(time.Millisecond))
	fmt.Fprintf(out, "скорость: %.0f хэш/сек\n", rate)
}

// resolveCharset разворачивает пресет в строку символов либо возвращает
// переданную произвольную строку как есть.
func resolveCharset(v string) string {
	switch v {
	case "digits":
		return "0123456789"
	case "lower":
		return "abcdefghijklmnopqrstuvwxyz"
	case "upper":
		return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "alnum":
		return "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "lower+digits":
		return "abcdefghijklmnopqrstuvwxyz0123456789"
	case "all":
		return printableASCII()
	default:
		return v
	}
}

// printableASCII возвращает все печатаемые ASCII-символы (0x20–0x7E).
func printableASCII() string {
	b := make([]byte, 0, 0x7F-0x20)
	for c := byte(0x20); c <= 0x7E; c++ {
		b = append(b, c)
	}
	return string(b)
}
