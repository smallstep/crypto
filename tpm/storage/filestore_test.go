package storage

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/schollz/jsonstore"
	"github.com/stretchr/testify/assert"
)

func TestFilestore_AddKey(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	store := new(jsonstore.JSONStore)
	store.Set("key-1st-key", serializedKey{Name: "1st-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	store.Data["key-bad-storage"] = nil
	tests := []struct {
		name   string
		key    *Key
		expErr error
	}{
		{
			name:   "already-exists",
			key:    &Key{Name: "1st-key"},
			expErr: errors.New("already exists"),
		},
		{
			name:   "an-error",
			key:    &Key{Name: "bad-storage"},
			expErr: errors.New("unexpected end of JSON input"),
		},
		{
			name:   "ok",
			key:    &Key{Name: "2nd-key"},
			expErr: nil,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Filestore{
				store: store,
			}
			err := s.AddKey(tc.key)
			if tc.expErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestFilestore_GetKey(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	store := new(jsonstore.JSONStore)
	store.Set("key-1st-key", serializedKey{Name: "1st-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	store.Data["key-bad-storage"] = nil
	tests := []struct {
		name    string
		keyName string
		want    *Key
		expErr  error
	}{
		{
			name:    "not-found",
			keyName: "non-existing-key",
			want:    nil,
			expErr:  errors.New("not found"),
		},
		{
			name:    "an-error",
			keyName: "bad-storage",
			want:    nil,
			expErr:  errors.New("unexpected end of JSON input"),
		},
		{
			name:    "ok",
			keyName: "1st-key",
			want:    &Key{Name: "1st-key", Data: []byte{0x1, 0x2, 0x3, 0x4}, AttestedBy: "1st-ak", Chain: []*x509.Certificate{}, CreatedAt: t0},
			expErr:  nil,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Filestore{
				store: store,
			}
			got, err := s.GetKey(tc.keyName)
			if tc.expErr != nil {
				assert.Nil(t, got)
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFilestore_DeleteKey(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	store := new(jsonstore.JSONStore)
	store.Set("key-1st-key", serializedKey{Name: "1st-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	store.Data["key-bad-storage"] = nil
	tests := []struct {
		name    string
		keyName string
		expErr  error
	}{
		{
			name:    "not-found",
			keyName: "non-existing-key",
			expErr:  errors.New("not found"),
		},
		{
			name:    "an-error",
			keyName: "bad-storage",
			expErr:  errors.New("unexpected end of JSON input"),
		},
		{
			name:    "ok",
			keyName: "1st-key",
			expErr:  nil,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Filestore{
				store: store,
			}

			err := s.DeleteKey(tc.keyName)
			if tc.expErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestFilestore_ListKeys(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	okStore := new(jsonstore.JSONStore)
	okStore.Set("key-1st-key", serializedKey{Name: "1st-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	okStore.Set("key-2nd-key", serializedKey{Name: "2nd-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	failStore := new(jsonstore.JSONStore)
	failStore.Set("key-1st-key", serializedKey{Name: "1st-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	failStore.Set("key-2nd-key", serializedKey{Name: "2nd-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	failStore.Data["key-bad-storage"] = nil
	tests := []struct {
		name   string
		store  *jsonstore.JSONStore
		want   []*Key
		expErr error
	}{
		{
			name:   "fail",
			store:  failStore,
			want:   []*Key{},
			expErr: errors.New("unexpected end of JSON input"),
		},
		{
			name:  "ok",
			store: okStore,
			want: []*Key{
				{
					Name:       "1st-key",
					Data:       []byte{1, 2, 3, 4},
					AttestedBy: "1st-ak",
					Chain:      []*x509.Certificate{},
					CreatedAt:  t0,
				},
				{
					Name:       "2nd-key",
					Data:       []byte{1, 2, 3, 4},
					AttestedBy: "1st-ak",
					Chain:      []*x509.Certificate{},
					CreatedAt:  t0,
				},
			},
			expErr: nil,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Filestore{
				store: tc.store,
			}
			got, err := s.ListKeys()
			if tc.expErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expErr.Error())
				assert.Empty(t, got)
				return
			}

			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestFilestore_ListKeyNames(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	store := new(jsonstore.JSONStore)
	store.Set("key-1st-key", serializedKey{Name: "1st-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	store.Set("key-2nd-key", serializedKey{Name: "2nd-key", Type: typeKey, Data: []byte{1, 2, 3, 4}, AttestedBy: "1st-ak", CreatedAt: t0})
	expected := []string{"1st-key", "2nd-key"}

	s := &Filestore{store: store}
	got := s.ListKeyNames()

	assert.ElementsMatch(t, expected, got)
}

func TestFilestore_AddAK(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	store := new(jsonstore.JSONStore)
	store.Set("ak-1st-ak", serializedAK{Name: "1st-ak", Type: typeKey, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	store.Data["ak-bad-storage"] = nil
	tests := []struct {
		name   string
		ak     *AK
		expErr error
	}{
		{
			name:   "already-exists",
			ak:     &AK{Name: "1st-ak"},
			expErr: errors.New("already exists"),
		},
		{
			name:   "an-error",
			ak:     &AK{Name: "bad-storage"},
			expErr: errors.New("unexpected end of JSON input"),
		},
		{
			name:   "ok",
			ak:     &AK{Name: "2nd-ak"},
			expErr: nil,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Filestore{
				store: store,
			}
			err := s.AddAK(tc.ak)
			if tc.expErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestFilestore_GetAK(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	store := new(jsonstore.JSONStore)
	store.Set("ak-1st-ak", serializedAK{Name: "1st-ak", Type: typeAK, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	store.Data["ak-bad-storage"] = nil
	tests := []struct {
		name   string
		akName string
		want   *AK
		expErr error
	}{
		{
			name:   "not-found",
			akName: "non-existing-ak",
			want:   nil,
			expErr: errors.New("not found"),
		},
		{
			name:   "an-error",
			akName: "bad-storage",
			want:   nil,
			expErr: errors.New("unexpected end of JSON input"),
		},
		{
			name:   "ok",
			akName: "1st-ak",
			want:   &AK{Name: "1st-ak", Data: []byte{0x1, 0x2, 0x3, 0x4}, Chain: []*x509.Certificate{}, CreatedAt: t0},
			expErr: nil,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Filestore{
				store: store,
			}
			got, err := s.GetAK(tc.akName)
			if tc.expErr != nil {
				assert.Nil(t, got)
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expErr.Error())
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFilestore_DeleteAK(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	store := new(jsonstore.JSONStore)
	store.Set("ak-1st-ak", serializedAK{Name: "1st-ak", Type: typeAK, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	store.Data["ak-bad-storage"] = nil
	tests := []struct {
		name   string
		akName string
		expErr error
	}{
		{
			name:   "not-found",
			akName: "non-existing-key",
			expErr: errors.New("not found"),
		},
		{
			name:   "an-error",
			akName: "bad-storage",
			expErr: errors.New("unexpected end of JSON input"),
		},
		{
			name:   "ok",
			akName: "1st-ak",
			expErr: nil,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Filestore{
				store: store,
			}

			err := s.DeleteAK(tc.akName)
			if tc.expErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expErr.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestFilestore_ListAKs(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	okStore := new(jsonstore.JSONStore)
	okStore.Set("ak-1st-ak", serializedAK{Name: "1st-ak", Type: typeKey, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	okStore.Set("ak-2nd-ak", serializedAK{Name: "2nd-ak", Type: typeKey, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	failStore := new(jsonstore.JSONStore)
	failStore.Set("ak-1st-ak", serializedAK{Name: "1st-ak", Type: typeKey, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	failStore.Set("ak-2nd-ak", serializedAK{Name: "2nd-ak", Type: typeKey, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	failStore.Data["ak-bad-storage"] = nil
	tests := []struct {
		name   string
		store  *jsonstore.JSONStore
		want   []*AK
		expErr error
	}{
		{
			name:   "fail",
			store:  failStore,
			want:   []*AK{},
			expErr: errors.New("unexpected end of JSON input"),
		},
		{
			name:  "ok",
			store: okStore,
			want: []*AK{
				{
					Name:      "1st-ak",
					Data:      []byte{1, 2, 3, 4},
					Chain:     []*x509.Certificate{},
					CreatedAt: t0,
				},
				{
					Name:      "2nd-ak",
					Data:      []byte{1, 2, 3, 4},
					Chain:     []*x509.Certificate{},
					CreatedAt: t0,
				},
			},
			expErr: nil,
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := &Filestore{
				store: tc.store,
			}
			got, err := s.ListAKs()
			if tc.expErr != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expErr.Error())
				assert.Empty(t, got)
				return
			}

			assert.NoError(t, err)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestFilestore_ListAKNames(t *testing.T) {
	t.Parallel()
	t0 := time.Time{} // we're hit by https://github.com/stretchr/testify/issues/950
	store := new(jsonstore.JSONStore)
	store.Set("ak-1st-ak", serializedAK{Name: "1st-ak", Type: typeKey, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	store.Set("ak-2nd-ak", serializedAK{Name: "2nd-ak", Type: typeKey, Data: []byte{1, 2, 3, 4}, CreatedAt: t0})
	expected := []string{"1st-ak", "2nd-ak"}

	s := &Filestore{store: store}
	got := s.ListAKNames()

	assert.ElementsMatch(t, expected, got)
}
