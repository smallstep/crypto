package tlsutil

import (
	"reflect"
	"sync"
	"testing"
)

func testCache() *sync.Map {
	m := new(sync.Map)
	m.Store("ok.test", &credentialsCacheElement{
		sni: "ok.test",
	})
	m.Store("bad.test", 123)
	m.Store("nil.test", nil)
	return m
}

func Test_newCredentialsCache(t *testing.T) {
	tests := []struct {
		name string
		want *credentialsCache
	}{
		{"ok", &credentialsCache{
			CacheStore: new(sync.Map),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newCredentialsCache(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newCredentialsCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_credentialsCache_Load(t *testing.T) {
	m := testCache()
	type fields struct {
		CacheStore *sync.Map
	}
	type args struct {
		domain string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *credentialsCacheElement
		want1  bool
	}{
		{"ok", fields{m}, args{"ok.test"}, &credentialsCacheElement{sni: "ok.test"}, true},
		{"nil", fields{m}, args{"nil.test"}, nil, false},
		{"fail", fields{m}, args{"fail.test"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &credentialsCache{
				CacheStore: tt.fields.CacheStore,
			}
			got, got1 := c.Load(tt.args.domain)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("credentialsCache.Load() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("credentialsCache.Load() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_credentialsCache_Store(t *testing.T) {
	type fields struct {
		CacheStore *sync.Map
	}
	type args struct {
		domain string
		v      *credentialsCacheElement
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{"ok", fields{new(sync.Map)}, args{"ok.test", &credentialsCacheElement{sni: "ok.test"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &credentialsCache{
				CacheStore: tt.fields.CacheStore,
			}
			c.Store(tt.args.domain, tt.args.v)

			got, got1 := c.Load(tt.args.domain)
			if !reflect.DeepEqual(got, tt.args.v) {
				t.Errorf("credentialsCache.Load() got = %v, want %v", got, tt.args.v)
			}
			if !got1 {
				t.Errorf("credentialsCache.Load() got1 = %v, want %v", got1, true)
			}
		})
	}
}

func Test_credentialsCache_Delete(t *testing.T) {
	m := testCache()
	type fields struct {
		CacheStore *sync.Map
	}
	type args struct {
		domain string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{"ok", fields{m}, args{"ok.test"}},
		{"deleted", fields{m}, args{"ok.test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &credentialsCache{
				CacheStore: tt.fields.CacheStore,
			}
			c.Delete(tt.args.domain)

			got, got1 := c.Load(tt.args.domain)
			if !reflect.DeepEqual(got, (*credentialsCacheElement)(nil)) {
				t.Errorf("credentialsCache.Load() got = %v, want %v", got, nil)
			}
			if got1 {
				t.Errorf("credentialsCache.Load() got1 = %v, want %v", got1, false)
			}
		})
	}
}

func Test_credentialsCache_Range(t *testing.T) {
	got := []*credentialsCacheElement{}
	want := []*credentialsCacheElement{
		{sni: "ok.test"},
	}
	type fields struct {
		CacheStore *sync.Map
	}
	type args struct {
		fn func(domain string, v *credentialsCacheElement) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{"ok", fields{testCache()}, args{func(domain string, v *credentialsCacheElement) bool {
			got = append(got, v)
			return true
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &credentialsCache{
				CacheStore: tt.fields.CacheStore,
			}
			c.Range(tt.args.fn)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("credentialsCache.Range() got = %v, want %v", got, want)
			}
		})
	}
}
