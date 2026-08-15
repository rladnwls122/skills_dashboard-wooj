package creds

// Which AWS credentials every client in this process signs with, and how to
// change them without restarting.
//
// The environment is read once at boot, so a key that arrives after the server
// started — or a session token that expires during the exercise — would
// otherwise mean editing a file and restarting, losing the sampled history in
// the process. Here the keys can be injected from the 설정 screen instead:
// pasted, or resolved from a local `aws` profile (SSO included) through the
// SDK's own shared-config chain.
//
// Precedence: 화면 주입 > 환경변수 > SDK 기본 체인(~/.aws, IRSA, 인스턴스 역할).
// Nothing is injected by default, so an environment that already works through
// the default chain keeps working exactly as before.
//
// Storage: the injected keys live either in this process's memory (기본값 —
// gone on restart) or, if the operator asks for it, in the same local SQLite
// the other settings use. Persisting writes a secret to disk in plain text;
// that is the operator's call to make, so it is a switch on the screen and not
// a default.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// Rows in the settings table. Prefixed like the environment variables they
// shadow so a `SELECT * FROM settings` during troubleshooting reads plainly.
const (
	kID      = "AWS_ACCESS_KEY_ID"
	kSecret  = "AWS_SECRET_ACCESS_KEY"
	kToken   = "AWS_SESSION_TOKEN"
	kExpires = "AWS_CREDENTIAL_EXPIRATION"
	kOrigin  = "AWS_CREDENTIAL_ORIGIN"
	kProfile = "AWS_CREDENTIAL_PROFILE"
)

// StoredKeys is what a settings save must leave alone: these rows are written
// by this file, not by the settings screen.
var StoredKeys = []string{kID, kSecret, kToken, kExpires, kOrigin, kProfile}

// A profile name reaches the shared-config loader as a lookup key. Everything
// outside the shape AWS itself allows is refused rather than escaped — the
// value comes from a text box on a page with no login.
var profileShape = regexp.MustCompile(`^[A-Za-z0-9_.@=+-]{1,128}$`)

// Injected is a credential set the screen put in force.
type Injected struct {
	Parsed
	// "paste" or "cli".
	Origin string
	// The profile a "cli" import came from. Kept so the refresh below can
	// re-read the same profile rather than guessing.
	Profile   string
	Persisted bool
}

// A CLI-imported session is refreshed this long before it expires. The SDK
// refreshes on its own schedule too; this is the margin used when the provider
// is asked for credentials directly.
const refreshMargin = 5 * time.Minute

type Manager struct {
	store *store.Store
	Now   func() time.Time

	mu sync.Mutex
	// Session-only store. Held here rather than in the panel cache: it must not
	// expire on its own, and it must not be reachable from the invalidation a
	// settings save performs.
	memory *Injected
	// One CLI re-read at a time. Every panel polls, and an expired token would
	// otherwise start a profile resolution per in-flight request.
	refreshing bool
	refreshed  *sync.Cond
}

func New(st *store.Store) *Manager {
	m := &Manager{store: st, Now: time.Now}
	m.refreshed = sync.NewCond(&m.mu)
	return m
}

func (m *Manager) fromDB() *Injected {
	if m.store == nil {
		return nil
	}
	rows, err := m.store.LoadSettings()
	if err != nil {
		// A locked or missing database must not take AWS access down with it.
		return nil
	}
	id, secret := rows[kID], rows[kSecret]
	if id == "" || secret == "" {
		return nil
	}
	origin := rows[kOrigin]
	if origin == "" {
		origin = "paste"
	}
	return &Injected{
		Parsed: Parsed{
			AccessKeyID:     id,
			SecretAccessKey: secret,
			SessionToken:    rows[kToken],
			Expiration:      rows[kExpires],
		},
		Origin:    origin,
		Profile:   rows[kProfile],
		Persisted: true,
	}
}

// Injected is what the screen put in force, memory first: a session-only
// injection is the more recent decision, and it is the one an operator makes
// when they specifically do not want the key on disk.
func (m *Manager) Injected() *Injected {
	m.mu.Lock()
	mem := m.memory
	m.mu.Unlock()
	if mem != nil {
		return mem
	}
	return m.fromDB()
}

func envCredentials() Parsed {
	return Parsed{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
}

// DefaultProfile is the profile the SDK would resolve on its own.
func DefaultProfile() string {
	if p := strings.TrimSpace(os.Getenv("AWS_PROFILE")); p != "" {
		return p
	}
	return "default"
}

type SetInput struct {
	Parsed
	Origin  string
	Profile string
	Persist bool
}

// Set replaces whatever is injected. Callers must reset the SDK clients
// afterwards — they capture the credential provider at construction.
func (m *Manager) Set(in SetInput) (*Injected, error) {
	next := Parsed{
		AccessKeyID:     strings.TrimSpace(in.AccessKeyID),
		SecretAccessKey: strings.TrimSpace(in.SecretAccessKey),
		SessionToken:    strings.TrimSpace(in.SessionToken),
		Expiration:      strings.TrimSpace(in.Expiration),
	}
	if problem := next.Problem(); problem != "" {
		return nil, errors.New(problem)
	}
	origin := in.Origin
	if origin != "cli" {
		origin = "paste"
	}
	record := &Injected{Parsed: next, Origin: origin, Profile: strings.TrimSpace(in.Profile), Persisted: in.Persist}

	if in.Persist {
		m.mu.Lock()
		m.memory = nil
		m.mu.Unlock()
		now := m.Now().UnixMilli()
		for _, kv := range [][2]string{
			{kID, record.AccessKeyID}, {kSecret, record.SecretAccessKey},
			{kToken, record.SessionToken}, {kExpires, record.Expiration},
			{kOrigin, record.Origin}, {kProfile, record.Profile},
		} {
			if err := m.store.SaveSetting(kv[0], kv[1], now); err != nil {
				return nil, fmt.Errorf("자격증명 저장 실패: %w", err)
			}
		}
		return record, nil
	}

	// Switching to session-only has to remove the disk copy too, or the next
	// restart silently resurrects a key the operator meant to stop using.
	m.clearStored()
	m.mu.Lock()
	m.memory = record
	m.mu.Unlock()
	return record, nil
}

func (m *Manager) clearStored() {
	if m.store == nil {
		return
	}
	now := m.Now().UnixMilli()
	for _, k := range StoredKeys {
		// "" is this table's delete signal (see store.SaveSetting).
		_ = m.store.SaveSetting(k, "", now)
	}
}

// Clear stops injecting. The process falls back to the environment and the SDK
// default chain, which is also what a fresh checkout does.
func (m *Manager) Clear() {
	m.mu.Lock()
	m.memory = nil
	m.mu.Unlock()
	m.clearStored()
}

// ImportProfile resolves a local `aws` profile through the SDK's own shared
// config chain — SSO, assume-role and a plain key file all included — and
// injects the concrete credentials it produced.
//
// Deliberately not left to the SDK's default provider: that chain hands back an
// opaque provider, and the point here is to *show* the operator which key and
// which expiry they are running on.
func (m *Manager) ImportProfile(ctx context.Context, profile string, persist bool) (*Injected, error) {
	name := strings.TrimSpace(profile)
	if name == "" {
		name = DefaultProfile()
	}
	if !profileShape.MatchString(name) {
		return nil, fmt.Errorf("프로파일 이름에 쓸 수 없는 문자가 있습니다: %s", name)
	}
	resolved, err := resolveProfile(ctx, name)
	if err != nil {
		return nil, err
	}
	return m.Set(SetInput{Parsed: resolved, Origin: "cli", Profile: name, Persist: persist})
}

// resolveProfile is the load-and-retrieve half, kept separate so the refresh
// path below does not recurse through Set's locking.
func resolveProfile(ctx context.Context, name string) (Parsed, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithSharedConfigProfile(name))
	if err != nil {
		return Parsed{}, fmt.Errorf("프로파일 %q 를 읽지 못했습니다: %w", name, err)
	}
	if cfg.Credentials == nil {
		return Parsed{}, fmt.Errorf("프로파일 %q 에 자격증명이 없습니다 — `aws configure --profile %s` 로 만든 뒤 다시 시도하세요", name, name)
	}
	got, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return Parsed{}, fmt.Errorf("프로파일 %q 의 세션을 읽지 못했습니다: %w — 만료된 SSO 세션이면 `aws sso login --profile %s` 로 다시 로그인하세요", name, err, name)
	}
	// The SDK chain reads the process environment before the profile. Silently
	// importing the environment's key under a profile's name would put the
	// wrong account on screen with the right label on it.
	if strings.Contains(got.Source, "EnvConfigCredentials") && os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		return Parsed{}, fmt.Errorf(
			"프로세스 환경변수(AWS_ACCESS_KEY_ID)가 프로파일보다 우선해서 %q 를 읽을 수 없습니다 — 환경변수를 지우고 서버를 다시 시작하거나, 키를 직접 붙여넣으세요", name)
	}
	out := Parsed{
		AccessKeyID:     got.AccessKeyID,
		SecretAccessKey: got.SecretAccessKey,
		SessionToken:    got.SessionToken,
	}
	if got.CanExpire {
		out.Expiration = got.Expires.UTC().Format(time.RFC3339)
	}
	if !out.Complete() {
		return Parsed{}, fmt.Errorf("프로파일 %q 가 자격증명을 내놓지 않았습니다", name)
	}
	return out, nil
}

// refreshFromProfile re-reads the profile behind an existing import, one flight
// at a time.
func (m *Manager) refreshFromProfile(ctx context.Context, current *Injected) (*Injected, error) {
	m.mu.Lock()
	for m.refreshing {
		m.refreshed.Wait()
	}
	m.refreshing = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.refreshing = false
		m.refreshed.Broadcast()
		m.mu.Unlock()
	}()

	// Another caller may have refreshed while this one waited.
	if latest := m.Injected(); latest != nil {
		if left := ExpiresInMs(latest.Expiration, m.Now().UnixMilli()); left == nil || *left >= refreshMargin.Milliseconds() {
			return latest, nil
		}
	}
	name := current.Profile
	if name == "" {
		name = DefaultProfile()
	}
	resolved, err := resolveProfile(ctx, name)
	if err != nil {
		return nil, err
	}
	return m.Set(SetInput{Parsed: resolved, Origin: "cli", Profile: name, Persist: current.Persisted})
}

// Provider is the credential provider handed to every SDK client, or nil to
// leave the SDK's own chain in charge.
//
// A provider function rather than a fixed value: temporary keys expire, and the
// SDK re-invokes the provider once `Expires` passes. That is what makes an
// `aws sso login` session keep working after the dashboard has been running for
// hours — the token is re-read from the profile instead of the whole process
// failing with InvalidClientTokenId.
func (m *Manager) Provider() aws.CredentialsProvider {
	if m.Injected() == nil {
		return nil
	}
	return aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		current := m.Injected()
		if current == nil {
			return aws.Credentials{}, errors.New("주입된 AWS 자격증명이 없습니다.")
		}
		if left := ExpiresInMs(current.Expiration, m.Now().UnixMilli()); left != nil && *left < refreshMargin.Milliseconds() {
			switch {
			case current.Origin == "cli":
				refreshed, err := m.refreshFromProfile(ctx, current)
				if err != nil {
					return aws.Credentials{}, err
				}
				current = refreshed
			case *left <= 0:
				return aws.Credentials{}, errors.New(
					"주입된 임시 자격증명이 만료되었습니다 — 설정 탭에서 세션을 다시 불러오거나 키를 다시 붙여넣으세요.")
			}
		}
		out := aws.Credentials{
			AccessKeyID:     current.AccessKeyID,
			SecretAccessKey: current.SecretAccessKey,
			SessionToken:    current.SessionToken,
			Source:          "dashboard-injected(" + current.Origin + ")",
		}
		if exp, ok := ParseExpiration(current.Expiration); ok {
			out.CanExpire = true
			out.Expires = exp
		}
		return out, nil
	})
}

// View is what the 설정 screen draws. Masked throughout — the secret and the
// session token never leave the server, in either direction.
func (m *Manager) View(nowMs int64) types.CredentialsView {
	inj := m.Injected()
	env := envCredentials()

	source := "chain"
	shown := env
	var origin *string
	var expiresIn *int64
	profile, expiration := "", ""
	persisted := false
	switch {
	case inj != nil:
		source = "screen"
		shown = inj.Parsed
		origin = types.Ptr(inj.Origin)
		profile = inj.Profile
		expiration = inj.Expiration
		persisted = inj.Persisted
		expiresIn = ExpiresInMs(inj.Expiration, nowMs)
	case env.Complete():
		source = "env"
	}

	return types.CredentialsView{
		Source:               source,
		Origin:               origin,
		Persisted:            persisted,
		Profile:              profile,
		AccessKeyIDMasked:    MaskKeyID(shown.AccessKeyID),
		SecretMasked:         MaskSecret(shown.SecretAccessKey),
		HasSessionToken:      shown.SessionToken != "",
		Temporary:            shown.Temporary(),
		Expiration:           expiration,
		ExpiresInMs:          expiresIn,
		EnvAccessKeyIDMasked: MaskKeyID(env.AccessKeyID),
		DefaultProfile:       DefaultProfile(),
	}
}
