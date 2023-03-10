package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/peterbourgon/diskv/v3"
)

// Dirstore is a concrete implementation of the TPMStore interface that
// stores TPM keys in a directory.
type Dirstore struct {
	store     *diskv.Diskv
	directory string
}

const tpmExtension = ".tpmobj"

func advancedTransform(key string) *diskv.PathKey {
	path := strings.Split(key, "/")
	last := len(path) - 1
	return &diskv.PathKey{
		Path:     path[:last],
		FileName: path[last] + tpmExtension,
	}
}

func inverseTransform(pathKey *diskv.PathKey) (key string) {
	ext := filepath.Ext(pathKey.FileName)
	if ext != tpmExtension { // skipping
		return ""
	}
	filename := pathKey.FileName[:len(pathKey.FileName)-len(tpmExtension)]
	p := filepath.Join(filepath.Join(pathKey.Path...), filename)
	if len(pathKey.Path) > 0 && pathKey.Path[0] == "" { // absolute path at "/"
		p = filepath.Join(string(filepath.Separator), p)
	}
	return p
}

// NewDirstore creates a new instance of a Direstore
func NewDirstore(directory string) *Dirstore {
	return &Dirstore{
		store: diskv.New(diskv.Options{
			BasePath:          directory,
			AdvancedTransform: advancedTransform,
			InverseTransform:  inverseTransform,
			CacheSizeMax:      1024 * 1024,
		}),
		directory: directory,
	}
}

func (s *Dirstore) ListKeys() ([]*Key, error) {
	var result = make([]*Key, 0)
	c := s.store.KeysPrefix(keyPrefix, nil)
	for k := range c {
		data, err := s.store.Read(k)
		if err != nil {
			return nil, fmt.Errorf("failed reading key from store: %w", err)
		}
		key := &Key{}
		if err := json.Unmarshal(data, key); err != nil {
			return nil, fmt.Errorf("failed unmarshaling key: %w", err)
		}
		result = append(result, key)
	}
	return result, nil
}

func (s *Dirstore) ListKeyNames() []string {
	var result = make([]string, 0)
	c := s.store.KeysPrefix(keyPrefix, nil)
	for k := range c {
		result = append(result, strings.TrimPrefix(k, keyPrefix))
	}
	return result
}

func (s *Dirstore) GetKey(name string) (*Key, error) {
	kk := keyForKey(name)
	if !s.store.Has(kk) {
		return nil, ErrNotFound
	}
	data, err := s.store.Read(kk)
	if err != nil {
		return nil, fmt.Errorf("failed reading key from store: %w", err)
	}
	key := &Key{}
	if err := json.Unmarshal(data, key); err != nil {
		return nil, fmt.Errorf("failed unmarshaling key: %w", err)
	}
	return key, nil
}

func (s *Dirstore) AddKey(key *Key) error {
	kk := keyForKey(key.Name)
	if s.store.Has(kk) {
		return ErrExists
	}
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed serializing key: %w", err)
	}
	if err := s.store.WriteStream(kk, bytes.NewBuffer(data), true); err != nil {
		return fmt.Errorf("failed writing key to disk: %w", err)
	}
	return nil
}

func (s *Dirstore) UpdateKey(key *Key) error {
	kk := keyForKey(key.Name)
	if !s.store.Has(kk) {
		return ErrNotFound
	}
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed serializing key: %w", err)
	}
	if err := s.store.WriteStream(kk, bytes.NewBuffer(data), true); err != nil {
		return fmt.Errorf("failed writing key to disk: %w", err)
	}
	return nil
}

func (s *Dirstore) DeleteKey(name string) error {
	key := keyForKey(name)
	if !s.store.Has(key) {
		return ErrNotFound
	}
	if err := s.store.Erase(key); err != nil {
		return fmt.Errorf("failed deleting key from disk: %w", err)
	}
	return nil
}

func (s *Dirstore) ListAKs() ([]*AK, error) {
	var result = make([]*AK, 0)
	c := s.store.KeysPrefix(akPrefix, nil)
	for k := range c {
		data, err := s.store.Read(k)
		if err != nil {
			return nil, fmt.Errorf("failed reading AK from store: %w", err)
		}
		ak := &AK{}
		if err := json.Unmarshal(data, ak); err != nil {
			return nil, fmt.Errorf("failed unmarshaling AK: %w", err)
		}
		result = append(result, ak)
	}
	return result, nil
}

func (s *Dirstore) ListAKNames() []string {
	var result = make([]string, 0)
	c := s.store.KeysPrefix(akPrefix, nil)
	for k := range c {
		result = append(result, strings.TrimPrefix(k, akPrefix))
	}
	return result
}

func (s *Dirstore) GetAK(name string) (*AK, error) {
	akKey := keyForAK(name)
	if !s.store.Has(akKey) {
		return nil, ErrNotFound
	}
	data, err := s.store.Read(akKey)
	if err != nil {
		return nil, fmt.Errorf("failed reading AK from store: %w", err)
	}
	ak := &AK{}
	if err := json.Unmarshal(data, ak); err != nil {
		return nil, fmt.Errorf("failed unmarshaling AK: %w", err)
	}
	return ak, nil
}

func (s *Dirstore) AddAK(ak *AK) error {
	akKey := keyForAK(ak.Name)
	if s.store.Has(akKey) {
		return ErrExists
	}
	data, err := json.Marshal(ak)
	if err != nil {
		return fmt.Errorf("failed serializing AK: %w", err)
	}
	if err := s.store.WriteStream(akKey, bytes.NewBuffer(data), true); err != nil {
		return fmt.Errorf("failed writing AK to disk: %w", err)
	}
	return nil
}

func (s *Dirstore) UpdateAK(ak *AK) error {
	akKey := keyForAK(ak.Name)
	if !s.store.Has(akKey) {
		return ErrNotFound
	}
	data, err := json.Marshal(ak)
	if err != nil {
		return fmt.Errorf("failed serializing AK: %w", err)
	}
	if err := s.store.WriteStream(akKey, bytes.NewBuffer(data), true); err != nil {
		return fmt.Errorf("failed writing AK to disk: %w", err)
	}
	return nil
}

func (s *Dirstore) DeleteAK(name string) error {
	key := keyForAK(name)
	if !s.store.Has(key) {
		return ErrNotFound
	}
	if err := s.store.Erase(key); err != nil {
		return fmt.Errorf("failed deleting AK from disk: %w", err)
	}
	return nil
}

func (s *Dirstore) Persist() error {
	return nil
}

func (s *Dirstore) Load() error {
	return nil
}

var _ TPMStore = (*Dirstore)(nil)
