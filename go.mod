module go.step.sm/crypto

go 1.20

require (
	cloud.google.com/go/kms v1.17.1
	filippo.io/edwards25519 v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.12.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.6.0
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys v0.10.0
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/aws/aws-sdk-go-v2/config v1.27.19
	github.com/aws/aws-sdk-go-v2/service/kms v1.32.2
	github.com/go-jose/go-jose/v3 v3.0.3
	github.com/go-piv/piv-go v1.11.0
	github.com/golang/mock v1.6.0
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.4.4
	github.com/googleapis/gax-go/v2 v2.12.4
	github.com/peterbourgon/diskv/v3 v3.0.1
	github.com/pkg/errors v0.9.1
	github.com/schollz/jsonstore v1.1.0
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/go-attestation v0.4.4-0.20240109183208-413678f90935
	github.com/stretchr/testify v1.9.0
	golang.org/x/crypto v0.24.0
	golang.org/x/net v0.26.0
	golang.org/x/sys v0.21.0
	google.golang.org/api v0.184.0
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.2
)

require (
	cloud.google.com/go v0.114.0 // indirect
	cloud.google.com/go/auth v0.5.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.2 // indirect
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	cloud.google.com/go/iam v1.1.8 // indirect
	cloud.google.com/go/longrunning v0.5.7 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.9.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/internal v0.7.1 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.28.0 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.19 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.20.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.24.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.13 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/metric v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	golang.org/x/oauth2 v0.21.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/genproto v0.0.0-20240604185151-ef581f913117 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240528184218-531527333157 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240604185151-ef581f913117 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
