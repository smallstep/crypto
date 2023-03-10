package storage

import (
	"bytes"
	"crypto/x509"
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

const tpmExtension = ".tpmkey"

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
			return nil, fmt.Errorf("error reading key from store: %w", err)
		}

		sk := &serializedKey{}
		if err := json.Unmarshal(data, sk); err != nil {
			return nil, fmt.Errorf("error unmarshaling key: %w", err)
		}

		result = append(result, &Key{Name: sk.Name, Data: sk.Data, AttestedBy: sk.AttestedBy, CreatedAt: sk.CreatedAt})
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
		return nil, fmt.Errorf("error reading key from store: %w", err)
	}

	sk := &serializedKey{}
	if err := json.Unmarshal(data, sk); err != nil {
		return nil, fmt.Errorf("error unmarshaling key: %w", err)
	}

	return &Key{Name: sk.Name, Data: sk.Data, AttestedBy: sk.AttestedBy, CreatedAt: sk.CreatedAt}, nil
}

func (s *Dirstore) AddKey(key *Key) error {
	kk := keyForKey(key.Name)
	if s.store.Has(kk) {
		return ErrExists
	}

	chain := make([][]byte, len(key.Chain))
	for i, cert := range key.Chain {
		chain[i] = cert.Raw
	}

	data, err := json.Marshal(serializedKey{Name: key.Name, Type: typeKey, Data: key.Data, AttestedBy: key.AttestedBy, Chain: chain, CreatedAt: key.CreatedAt})
	if err != nil {
		return fmt.Errorf("error serializing key: %w", err)
	}

	if err := s.store.WriteStream(kk, bytes.NewBuffer(data), true); err != nil {
		return fmt.Errorf("error writing key to disk: %w", err)
	}
	return nil
}

func (s *Dirstore) UpdateKey(key *Key) error {
	kk := keyForKey(key.Name)
	if !s.store.Has(kk) {
		return ErrNotFound
	}
	chain := make([][]byte, len(key.Chain))
	for i, cert := range key.Chain {
		chain[i] = cert.Raw
	}
	data, err := json.Marshal(serializedKey{Name: key.Name, Type: typeKey, Data: key.Data, AttestedBy: key.AttestedBy, Chain: chain, CreatedAt: key.CreatedAt})
	if err != nil {
		return fmt.Errorf("error serializing key: %w", err)
	}
	if err := s.store.WriteStream(kk, bytes.NewBuffer(data), true); err != nil {
		return fmt.Errorf("error writing key to disk: %w", err)
	}
	return nil
}

func (s *Dirstore) DeleteKey(name string) error {
	key := keyForKey(name)
	if !s.store.Has(key) {
		return ErrNotFound
	}
	if err := s.store.Erase(key); err != nil {
		return fmt.Errorf("error deleting key from disk: %w", err)
	}
	return nil
}

func (s *Dirstore) ListAKs() ([]*AK, error) {
	var result = make([]*AK, 0)
	c := s.store.KeysPrefix(akPrefix, nil)
	for k := range c {
		data, err := s.store.Read(k)
		if err != nil {
			return nil, fmt.Errorf("error reading AK from store: %w", err)
		}

		sak := &serializedAK{}
		if err := json.Unmarshal(data, sak); err != nil {
			return nil, fmt.Errorf("error unmarshaling AK: %w", err)
		}

		chain := make([]*x509.Certificate, len(sak.Chain))
		for i, certBytes := range sak.Chain {
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, fmt.Errorf("failed parsing certificate: %w", err)
			}
			chain[i] = cert
		}

		result = append(result, &AK{Name: sak.Name, Data: sak.Data, Chain: chain, CreatedAt: sak.CreatedAt})
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
		return nil, fmt.Errorf("error reading AK from store: %w", err)
	}

	sak := &serializedAK{}
	if err := json.Unmarshal(data, sak); err != nil {
		return nil, fmt.Errorf("error unmarshaling AK: %w", err)
	}

	chain := make([]*x509.Certificate, len(sak.Chain))
	for i, certBytes := range sak.Chain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing certificate: %w", err)
		}
		chain[i] = cert
	}

	return &AK{Name: sak.Name, Data: sak.Data, Chain: chain, CreatedAt: sak.CreatedAt}, nil
}

func (s *Dirstore) AddAK(ak *AK) error {
	akKey := keyForAK(ak.Name)
	if s.store.Has(akKey) {
		return ErrExists
	}
	chain := make([][]byte, len(ak.Chain))
	for i, cert := range ak.Chain {
		chain[i] = cert.Raw
	}
	data, err := json.Marshal(serializedAK{Name: ak.Name, Type: typeAK, Data: ak.Data, Chain: chain, CreatedAt: ak.CreatedAt})
	if err != nil {
		return fmt.Errorf("error serializing AK: %w", err)
	}
	if err := s.store.WriteStream(akKey, bytes.NewBuffer(data), true); err != nil {
		return fmt.Errorf("error writing AK to disk: %w", err)
	}
	return nil
}

func (s *Dirstore) UpdateAK(ak *AK) error {
	akKey := keyForAK(ak.Name)
	if !s.store.Has(akKey) {
		return ErrNotFound
	}
	chain := make([][]byte, len(ak.Chain))
	for i, cert := range ak.Chain {
		chain[i] = cert.Raw
	}
	data, err := json.Marshal(serializedAK{Name: ak.Name, Type: typeAK, Data: ak.Data, Chain: chain, CreatedAt: ak.CreatedAt})
	if err != nil {
		return fmt.Errorf("error serializing AK: %w", err)
	}
	if err := s.store.WriteStream(akKey, bytes.NewBuffer(data), true); err != nil {
		return fmt.Errorf("error writing AK to disk: %w", err)
	}
	return nil
}

func (s *Dirstore) DeleteAK(name string) error {
	key := keyForAK(name)
	if !s.store.Has(key) {
		return ErrNotFound
	}
	if err := s.store.Erase(key); err != nil {
		return fmt.Errorf("error deleting AK from disk: %w", err)
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
