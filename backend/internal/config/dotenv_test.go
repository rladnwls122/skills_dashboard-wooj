package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEnvShapes(t *testing.T) {
	pairs := ParseEnv(strings.Join([]string{
		"# a comment",
		"",
		"AWS_REGION=ap-northeast-2",
		"export WAF_SCOPE=CLOUDFRONT",
		"  APP_LOG_GROUP = /aws/eks/app  ",
		"API_ADDR=127.0.0.1:8787 # where it listens",
		`CORS_ALLOW_ORIGINS="http://localhost:3100,http://127.0.0.1:3100"`,
		"SINGLE='literal $not expanded'",
		"URL=http://h/p#frag",
		"not a pair",
		"1BAD=x",
		"EMPTY=",
		"COMMENTED=  # 값 없이 메모만",
	}, "\n"))

	want := map[string]string{
		"AWS_REGION":         "ap-northeast-2",
		"WAF_SCOPE":          "CLOUDFRONT",
		"APP_LOG_GROUP":      "/aws/eks/app",
		"API_ADDR":           "127.0.0.1:8787",
		"CORS_ALLOW_ORIGINS": "http://localhost:3100,http://127.0.0.1:3100",
		"SINGLE":             "literal $not expanded",
		"URL":                "http://h/p#frag",
		"EMPTY":              "",
		"COMMENTED":          "",
	}
	for key, expect := range want {
		if got := pairs[key]; got != expect {
			t.Errorf("%s = %q, want %q", key, got, expect)
		}
	}
	if _, ok := pairs["1BAD"]; ok {
		t.Error("an invalid key was accepted")
	}
	if len(pairs) != len(want) {
		t.Errorf("parsed %d keys, want %d: %v", len(pairs), len(want), pairs)
	}
}

func TestParseEnvStripsBOM(t *testing.T) {
	if got := ParseEnv("\ufeffAWS_REGION=ap-northeast-2")["AWS_REGION"]; got != "ap-northeast-2" {
		t.Errorf("AWS_REGION = %q with a BOM present", got)
	}
}

func TestLoadDotenvDoesNotOverrideEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	body := "DOTENV_T_NEW=fromfile\nDOTENV_T_SET=fromfile\nDOTENV_T_BLANK=\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOTENV_T_SET", "fromenv")

	res := LoadDotenv(path)
	if res.Path != path {
		t.Fatalf("path = %q, want %q", res.Path, path)
	}
	// Setenv registers the cleanup that undoes what LoadDotenv sets.
	t.Cleanup(func() { os.Unsetenv("DOTENV_T_NEW") })

	if got := os.Getenv("DOTENV_T_NEW"); got != "fromfile" {
		t.Errorf("DOTENV_T_NEW = %q, want fromfile", got)
	}
	if got := os.Getenv("DOTENV_T_SET"); got != "fromenv" {
		t.Errorf("DOTENV_T_SET = %q, want the environment to win", got)
	}
	if _, ok := os.LookupEnv("DOTENV_T_BLANK"); ok {
		t.Error("a blank value in .env was applied")
	}
	if len(res.Applied) != 1 || res.Applied[0] != "DOTENV_T_NEW" {
		t.Errorf("applied = %v", res.Applied)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "DOTENV_T_SET" {
		t.Errorf("skipped = %v", res.Skipped)
	}
}

func TestLoadDotenvMissingFileIsNormal(t *testing.T) {
	// Run from a directory with no .env so no candidate resolves.
	t.Chdir(t.TempDir())
	if res := LoadDotenv(filepath.Join(t.TempDir(), "nope.env")); res.Path != "" {
		t.Errorf("path = %q, want empty for a missing file", res.Path)
	}
}
