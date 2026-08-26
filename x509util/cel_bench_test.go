package x509util

import "testing"

// BenchmarkWithTemplate compares a template that uses the cel function against
// one that does not. The environment is shared, so a template with no cel call
// pays nothing for the function being available — which matters because that
// describes every template written before this existed.
func BenchmarkWithTemplate(b *testing.B) {
	cr, _ := createCertificateRequest(b, "foo", []string{"foo.com"})
	data := TemplateData{
		SubjectKey: Subject{CommonName: "example", Country: []string{"ES"}},
		SANsKey:    CreateSANs([]string{"foo.com", "bar.com"}),
	}

	benchmarks := []struct {
		name string
		text string
	}{
		{"no cel call", `{"subject":{"commonName":{{ toJson .Subject.CommonName }}}}`},
		{"one cel call", `{"subject":{"commonName":{{ cel "Subject.CommonName" | toJson }}}}`},
		{"five cel calls", `{"subject":{"commonName":{{ cel "Subject.CommonName" | toJson }},` +
			`"country":{{ cel "Subject.Country" | toJson }},` +
			`"organization":{{ cel "[Subject.CommonName]" | toJson }},` +
			`"locality":{{ cel "[Subject.CommonName.upperAscii()]" | toJson }},` +
			`"province":{{ cel "SANs.map(s, s.Value)" | toJson }}}}`},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			fn := WithTemplate(bm.text, data)
			b.ReportAllocs()
			for b.Loop() {
				var o Options
				if err := fn(cr, &o); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
