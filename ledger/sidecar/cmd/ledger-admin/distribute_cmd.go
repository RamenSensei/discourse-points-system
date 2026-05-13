package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/forum-points/ledger/internal/rewards"
	"github.com/forum-points/ledger/internal/store"
)

// cmdDistribute backfills startup rewards to existing Discourse users.
//
// Two input modes:
//  1. --stdin             : read "discourse_id,username[,has_posted]" CSV lines from stdin
//  2. --discourse-api ... : crawl Discourse Admin API for active users
//
// Idempotent: reward_events dedup means re-running is safe.
func cmdDistribute(args []string) {
	fs := flag.NewFlagSet("distribute", flag.ExitOnError)
	stdinMode := fs.Bool("stdin", false, "read CSV (discourse_id,username[,has_posted]) from stdin")
	apiURL := fs.String("discourse-api", "", "Discourse base URL for admin API mode (e.g. https://forum.example.com)")
	apiKey := fs.String("api-key", "", "Discourse Admin API key (required for --discourse-api)")
	apiUser := fs.String("api-username", "system", "Discourse Admin API username")
	maxUsers := fs.Int("max", 0, "stop after paying this many users (0 = unlimited)")
	dryRun := fs.Bool("dry-run", false, "do not apply, just print what would happen")
	includeFirstPost := fs.Bool("include-first-post", true, "also pay first_post_ever bonus to users with ≥1 post")
	fs.Parse(args)

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	privHex := os.Getenv("ADMIN_PRIV_KEY_HEX")
	if privHex == "" {
		log.Fatal("ADMIN_PRIV_KEY_HEX is required")
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		log.Fatal("ADMIN_PRIV_KEY_HEX must be 128-char hex Ed25519 private key")
	}
	adminPriv := ed25519.PrivateKey(priv)
	adminPub := adminPriv.Public().(ed25519.PublicKey)

	ctx := context.Background()
	pg, err := store.NewPGStore(ctx, dsn)
	if err != nil {
		log.Fatalf("connect pg: %v", err)
	}
	defer pg.Close()
	if err := pg.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	svc := &rewards.Service{
		Store:        pg,
		Rewards:      pg,
		AdminPrivKey: adminPriv,
		AdminPubKey:  adminPub,
	}

	var feed <-chan backfillRow
	switch {
	case *stdinMode:
		feed = streamStdin()
	case *apiURL != "":
		if *apiKey == "" {
			log.Fatal("--api-key required for --discourse-api mode")
		}
		feed = streamDiscourseAPI(*apiURL, *apiKey, *apiUser)
	default:
		log.Fatal("specify --stdin or --discourse-api <url>")
	}

	count := 0
	paidSignup := 0
	paidFirstPost := 0
	skipped := 0
	for row := range feed {
		if *maxUsers > 0 && count >= *maxUsers {
			break
		}
		count++

		if row.DscID <= 0 || row.Username == "" {
			fmt.Fprintf(os.Stderr, "skip invalid row: %+v\n", row)
			continue
		}

		// 1. signup_bonus
		k := fmt.Sprintf("user:%d", row.DscID)
		paid, err := payIfNotAlready(ctx, svc, "signup_bonus", k, row.DscID, row.Username, *dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "user %d (%s): signup_bonus FAILED %v\n", row.DscID, row.Username, err)
			continue
		}
		if paid {
			paidSignup++
		} else {
			skipped++
		}

		// 2. first_post_ever if applicable
		if *includeFirstPost && row.HasPosted {
			paid2, err := payIfNotAlready(ctx, svc, "first_post_ever", k, row.DscID, row.Username, *dryRun)
			if err != nil {
				fmt.Fprintf(os.Stderr, "user %d (%s): first_post_ever FAILED %v\n", row.DscID, row.Username, err)
				continue
			}
			if paid2 {
				paidFirstPost++
			}
		}

		if count%50 == 0 {
			fmt.Printf("…processed %d users (signup_bonus=%d, first_post=%d, skipped=%d)\n",
				count, paidSignup, paidFirstPost, skipped)
		}
	}
	fmt.Println()
	fmt.Printf("done: processed=%d signup_bonus=%d first_post_ever=%d skipped=%d (dry_run=%v)\n",
		count, paidSignup, paidFirstPost, skipped, *dryRun)
}

type backfillRow struct {
	DscID     int64
	Username  string
	HasPosted bool
}

func payIfNotAlready(ctx context.Context, svc *rewards.Service, eventType, eventKey string, dscID int64, username string, dryRun bool) (bool, error) {
	already, err := svc.Rewards.RewardEventExists(ctx, eventType, eventKey)
	if err != nil {
		return false, err
	}
	if already {
		return false, nil
	}
	amount, enabled, err := svc.Rewards.GetRewardAmount(ctx, eventType)
	if err != nil {
		return false, err
	}
	if !enabled || amount <= 0 {
		return false, nil
	}
	if dryRun {
		fmt.Printf("[dry-run] would pay %s amount=%d → user %d (%s)\n", eventType, amount, dscID, username)
		return true, nil
	}
	tx, err := svc.SignAndApplyTransfer(ctx, dscID, username, amount, "backfill:"+eventType)
	if err != nil {
		return false, err
	}
	if err := svc.Rewards.RecordRewardEvent(ctx, eventType, eventKey, tx.TxHash); err != nil {
		log.Printf("WARN: %s/%s dedup record failed but tx applied: %v", eventType, eventKey, err)
	}
	return true, nil
}

// --- stdin CSV feed ---

func streamStdin() <-chan backfillRow {
	out := make(chan backfillRow, 32)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, ",")
			if len(parts) < 2 {
				fmt.Fprintf(os.Stderr, "skip malformed line: %q\n", line)
				continue
			}
			id, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			if err != nil {
				continue
			}
			row := backfillRow{
				DscID:    id,
				Username: strings.TrimSpace(parts[1]),
			}
			if len(parts) >= 3 {
				v := strings.TrimSpace(parts[2])
				row.HasPosted = v == "true" || v == "1" || v == "yes"
			}
			out <- row
		}
	}()
	return out
}

// --- Discourse Admin API feed ---
//
// Uses /admin/users/list/active.json?page=N. Each user object:
//   { "id": ..., "username": "...", "post_count": ..., "active": true, "approved": true }
// We filter approved + active + post_count >= 0 (we accept all, but HasPosted = post_count > 0).

type discourseUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	PostCount int    `json:"post_count"`
	Active    bool   `json:"active"`
	Approved  bool   `json:"approved"`
}

func streamDiscourseAPI(base, key, user string) <-chan backfillRow {
	out := make(chan backfillRow, 32)
	go func() {
		defer close(out)
		client := &http.Client{Timeout: 30 * time.Second}
		for page := 1; ; page++ {
			url := fmt.Sprintf("%s/admin/users/list/active.json?page=%d&show_emails=false", strings.TrimRight(base, "/"), page)
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("Api-Key", key)
			req.Header.Set("Api-Username", user)
			req.Header.Set("Accept", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "discourse API fetch page %d: %v\n", page, err)
				return
			}
			if resp.StatusCode != 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				fmt.Fprintf(os.Stderr, "discourse API HTTP %d: %s\n", resp.StatusCode, string(body))
				return
			}
			var users []discourseUser
			if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
				resp.Body.Close()
				fmt.Fprintf(os.Stderr, "discourse API decode page %d: %v\n", page, err)
				return
			}
			resp.Body.Close()
			if len(users) == 0 {
				return // no more pages
			}
			for _, u := range users {
				if !u.Active || !u.Approved {
					continue
				}
				out <- backfillRow{DscID: u.ID, Username: u.Username, HasPosted: u.PostCount > 0}
			}
			// Be nice to Discourse:
			time.Sleep(150 * time.Millisecond)
		}
	}()
	return out
}
