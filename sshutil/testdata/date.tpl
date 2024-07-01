{
	"type": "{{ .Type }}",
	"keyId": "{{ .KeyID }}",
	"principals": {{ toJson .Principals }},
	"extensions": {{ toJson .Extensions }},
	"validAfter": {{ now | toJson }},
	"validBefore": {{ now | dateModify .Webhooks.Test.validity | toJson }}
}