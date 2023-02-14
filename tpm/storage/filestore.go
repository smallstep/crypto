package storage

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/schollz/jsonstore"
)

// Filestore is a concrete implementation of the TPMStore interface that
// keeps an in-memory map of AKs and TPM Keys. The current state of the
// in-memory storage can be persisted to a file.
type Filestore struct {
	store    *jsonstore.JSONStore
	filepath string
}

// NewFilestore creates a new instance of a Filestore
//
// TODO: provide options for filepath (with default),
// gzip, persistence en-/disabled, ... ?
func NewFilestore(filepath string) *Filestore {
	return &Filestore{
		store:    new(jsonstore.JSONStore),
		filepath: filepath,
	}
}

func (s *Filestore) AddKey(k *Key) error {
	kk := keyForKey(k.Name)
	if err := s.store.Get(kk, nil); err != nil {
		nsk := &jsonstore.NoSuchKeyError{}
		if errors.As(err, nsk) {
			return s.store.Set(kk, serializedKey{Name: k.Name, Type: typeKey, Data: k.Data, AttestedBy: k.AttestedBy, CreatedAt: k.CreatedAt})
		}
		return err
	}

	return ErrExists
}

func (s *Filestore) AddAK(ak *AK) error {
	ka := keyForAK(ak.Name)
	if err := s.store.Get(ka, nil); err != nil {
		nsk := &jsonstore.NoSuchKeyError{}
		if errors.As(err, nsk) {
			return s.store.Set(ka, serializedAK{Name: ak.Name, Type: typeKey, Data: ak.Data, CreatedAt: ak.CreatedAt})
		}
		return err
	}

	return ErrExists
}

func (s *Filestore) GetKey(name string) (*Key, error) {
	sk := &serializedKey{}
	if err := s.store.Get(keyForKey(name), sk); err != nil {
		nsk := &jsonstore.NoSuchKeyError{}
		if errors.As(err, nsk) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &Key{Name: sk.Name, Data: sk.Data, AttestedBy: sk.AttestedBy, CreatedAt: sk.CreatedAt}, nil
}

func (s *Filestore) GetAK(name string) (*AK, error) {
	ak := &serializedAK{}
	if err := s.store.Get(keyForAK(name), ak); err != nil {
		nsk := &jsonstore.NoSuchKeyError{}
		if errors.As(err, nsk) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &AK{Name: ak.Name, Data: ak.Data, CreatedAt: ak.CreatedAt}, nil
}

func (s *Filestore) DeleteKey(name string) error {
	kk := keyForKey(name)
	if err := s.store.Get(kk, nil); err != nil {
		nsk := &jsonstore.NoSuchKeyError{}
		if errors.As(err, nsk) {
			return ErrNotFound
		}
		return err
	}

	s.store.Delete(kk)
	return nil
}

func (s *Filestore) DeleteAK(name string) error {
	ka := keyForAK(name)
	if err := s.store.Get(ka, nil); err != nil {
		nsk := &jsonstore.NoSuchKeyError{}
		if errors.As(err, nsk) {
			return ErrNotFound
		}
		return err
	}

	s.store.Delete(ka)
	return nil
}

func (s *Filestore) ListKeys() ([]*Key, error) {
	keys := s.store.GetAll(regexp.MustCompile(keyPrefix))
	var result = make([]*Key, 0, len(keys))
	for _, v := range keys {
		sk := &serializedKey{}
		err := json.Unmarshal(v, sk)
		if err != nil {
			return nil, err
		}
		result = append(result, &Key{Name: sk.Name, Data: sk.Data, AttestedBy: sk.AttestedBy, CreatedAt: sk.CreatedAt})
	}

	return result, nil
}

func (s *Filestore) ListAKs() ([]*AK, error) {
	aks := s.store.GetAll(regexp.MustCompile(akPrefix))
	var result = make([]*AK, 0, len(aks))
	for _, v := range aks {
		ak := &serializedAK{}
		err := json.Unmarshal(v, ak)
		if err != nil {
			return nil, err
		}
		result = append(result, &AK{Name: ak.Name, Data: ak.Data, CreatedAt: ak.CreatedAt})
	}

	return result, nil
}

func (s *Filestore) ListKeyNames() []string {
	keys := s.store.Keys()
	var result = make([]string, 0, len(keys))
	for _, k := range keys {
		if strings.HasPrefix(k, keyPrefix) {
			result = append(result, strings.TrimPrefix(k, keyPrefix))
		}
	}

	return result
}

func (s *Filestore) ListAKNames() []string {
	keys := s.store.Keys()
	var result = make([]string, 0, len(keys))
	for _, k := range keys {
		if strings.HasPrefix(k, akPrefix) {
			result = append(result, strings.TrimPrefix(k, akPrefix))
		}
	}

	return result
}

func (s *Filestore) Persist() error {
	return jsonstore.Save(s.store, s.filepath)
}

func (s *Filestore) Load() error {
	store, err := jsonstore.Open(s.filepath)
	if err != nil { // TODO: handle different types of errors related to file system?
		store = new(jsonstore.JSONStore)
	}
	s.store = store
	return nil
}

var _ TPMStore = (*Filestore)(nil)
