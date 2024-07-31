package attestation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	baseURL := "http://localhost:1337"
	type args struct {
		tpmAttestationCABaseURL string
		options                 []Option
	}
	tests := []struct {
		name       string
		args       args
		assertFunc assert.ValueAssertionFunc
		wantErr    bool
	}{
		{
			name: "ok/no-options",
			args: args{
				tpmAttestationCABaseURL: baseURL,
				options:                 nil,
			},
			assertFunc: func(tt assert.TestingT, i1 any, i2 ...any) bool {
				if assert.IsType(t, &Client{}, i1) {
					c, _ := i1.(*Client)
					if assert.NotNil(t, c) {
						if assert.NotNil(t, c.baseURL) {
							assert.Equal(t, baseURL, c.baseURL.String())
						}
						if assert.NotNil(t, c.client) {
							assert.Equal(t, 10*time.Second, c.client.Timeout)
						}
						return true
					}
				}
				return false
			},
			wantErr: false,
		},
		{
			name: "ok/with-options",
			args: args{
				tpmAttestationCABaseURL: baseURL,
				options:                 []Option{WithInsecure(), WithRootsFile("testdata/roots.pem")},
			},
			assertFunc: func(tt assert.TestingT, i1 any, i2 ...any) bool {
				if assert.IsType(t, &Client{}, i1) {
					c, _ := i1.(*Client)
					if assert.NotNil(t, c) {
						if assert.NotNil(t, c.baseURL) {
							assert.Equal(t, baseURL, c.baseURL.String())
						}
						if assert.NotNil(t, c.client) {
							assert.Equal(t, 10*time.Second, c.client.Timeout)
						}
						return true
					}
				}
				return false
			},
			wantErr: false,
		},
		{
			name: "fail/non-existing-roots",
			args: args{
				tpmAttestationCABaseURL: baseURL,
				options:                 []Option{WithInsecure(), WithRootsFile("testdata/non-existing-roots.pem")},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewClient(tt.args.tpmAttestationCABaseURL, tt.args.options...)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.True(t, tt.assertFunc(t, got))
		})
	}
}
