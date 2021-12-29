package step

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func mustHome(t *testing.T) string {
	t.Helper()

	homePath = os.Getenv(HomeEnv)
	if homePath != "" {
		return homePath
	}
	usr, err := user.Current()
	if err == nil && usr.HomeDir != "" {
		return usr.HomeDir
	}
	t.Fatal("error obtaining home directory")
	return ""
}

func TestPath(t *testing.T) {
	tmp := stepPath
	home := mustHome(t)
	t.Cleanup(func() {
		stepPath = tmp
	})

	tests := []struct {
		name string
		want string
	}{
		{"default", filepath.Join(home, ".step")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Path(); got != tt.want {
				t.Errorf("Path() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHome(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"default", mustHome(t)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Home(); got != tt.want {
				t.Errorf("Home() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAbs(t *testing.T) {
	home := mustHome(t)
	abs, err := filepath.Abs("./foo/bar/zar")
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"abs", args{"/foo/bar/zar"}, "/foo/bar/zar"},
		{"home", args{"~/foo/bar/zar"}, filepath.Join(home, "foo", "bar", "zar")},
		{"relative", args{"./foo/bar/zar"}, abs},
		{"step", args{"foo/bar/zar"}, filepath.Join(home, ".step", "foo", "bar", "zar")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Abs(tt.args.path); got != tt.want {
				t.Errorf("Abs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getUserHomeDir(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"ok", os.Getenv("HOME")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getUserHomeDir(); got != tt.want {
				t.Errorf("getUserHomeDir() = %v, want %v", got, tt.want)
			}
		})
	}
}
