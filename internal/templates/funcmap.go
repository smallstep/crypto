package templates

import (
	"errors"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"go.step.sm/crypto/jose"
)

// GetFuncMap returns the list of functions provided by sprig. It adds the
// functions "formatTime", "toTime", "mustToTime", and changes the function
// "fail".
//
// The "toTime" function receives a time or a Unix epoch and returns a time.Time
// in UTC. The "formatTime" function uses "toTime" and formats the resulting
// time using RFC3339. The functions "parseTime" and "mustParseTime" parses a
// string and returns the time.Time it represents. The "toLayout" function
// converts strings like "time.RFC3339" or "time.UnixDate" to the actual layout
// represented by the Go constant with the same name. The "fail" function sets
// the provided message, so that template errors are reported directly to the
// template without having the wrapper that text/template adds.
//
//	{{ toTime }}
//		=> time.Now().UTC()
//	{{ .Token.nbf | toTime }}
//		=> time.Unix(.Token.nbf, 0).UTC()
//	{{ .Token.nbf | formatTime }}
//		=> time.Unix(.Token.nbf, 0).UTC().Format(time.RFC3339)
//	{{ "2024-07-02T23:16:02Z" | parseTime }}
//		=> time.Parse(time.RFC3339, "2024-07-02T23:16:02Z")
//	{{ parseTime "time.RFC339" "2024-07-02T23:16:02Z" }}
//		=> time.Parse(time.RFC3339, "2024-07-02T23:16:02Z")
//	{{ parseTime "time.UnixDate" "Tue Jul  2 16:20:48 PDT 2024" "America/Los_Angeles" }}
//		=> loc, _ := time.LoadLocation("America/Los_Angeles")
//		   time.ParseInLocation(time.UnixDate, "Tue Jul  2 16:20:48 PDT 2024", loc)
//	{{ toLayout "time.RFC3339" }}
//		=> time.RFC3339
//
// sprig "env" and "expandenv" functions are removed to avoid the leak of
// information.
func GetFuncMap(failMessage *string) template.FuncMap {
	m := sprig.TxtFuncMap()
	delete(m, "env")
	delete(m, "expandenv")
	m["fail"] = func(msg string) (string, error) {
		*failMessage = msg
		return "", errors.New(msg)
	}
	m["formatTime"] = formatTime
	m["toTime"] = toTime
	m["parseTime"] = parseTime
	m["mustParseTime"] = mustParseTime
	m["toLayout"] = toLayout
	return m
}

func toTime(v any) time.Time {
	var t time.Time
	switch date := v.(type) {
	case time.Time:
		t = date
	case *time.Time:
		t = *date
	case int64:
		t = time.Unix(date, 0)
	case float64: // from json
		t = time.Unix(int64(date), 0)
	case int:
		t = time.Unix(int64(date), 0)
	case int32:
		t = time.Unix(int64(date), 0)
	case jose.NumericDate:
		t = date.Time()
	case *jose.NumericDate:
		t = date.Time()
	default:
		t = time.Now()
	}
	return t.UTC()
}

func formatTime(v any) string {
	return toTime(v).Format(time.RFC3339)
}

func parseTime(v ...string) time.Time {
	t, _ := mustParseTime(v...)
	return t
}

func mustParseTime(v ...string) (time.Time, error) {
	switch len(v) {
	case 0:
		return time.Now().UTC(), nil
	case 1:
		return time.Parse(time.RFC3339, v[0])
	case 2:
		layout := toLayout(v[0])
		return time.Parse(layout, v[1])
	case 3:
		layout := toLayout(v[0])
		loc, err := time.LoadLocation(v[2])
		if err != nil {
			return time.Time{}, err
		}
		return time.ParseInLocation(layout, v[1], loc)
	default:
		return time.Time{}, errors.New("unsupported number of parameters")
	}
}

func toLayout(fmt string) string {
	if !strings.HasPrefix(fmt, "time.") {
		return fmt
	}

	switch fmt {
	case "time.Layout":
		return time.Layout
	case "time.ANSIC":
		return time.ANSIC
	case "time.UnixDate":
		return time.UnixDate
	case "time.RubyDate":
		return time.RubyDate
	case "time.RFC822":
		return time.RFC822
	case "time.RFC822Z":
		return time.RFC822Z
	case "time.RFC850":
		return time.RFC850
	case "time.RFC1123":
		return time.RFC1123
	case "time.RFC1123Z":
		return time.RFC1123Z
	case "time.RFC3339":
		return time.RFC3339
	case "time.RFC3339Nano":
		return time.RFC3339Nano
	// From the ones bellow, only time.DateTime will parse a complete date.
	case "time.Kitchen":
		return time.Kitchen
	case "time.Stamp":
		return time.Stamp
	case "time.StampMilli":
		return time.StampMilli
	case "time.StampMicro":
		return time.StampMicro
	case "time.StampNano":
		return time.StampNano
	case "time.DateTime":
		return time.DateTime
	case "time.DateOnly":
		return time.DateOnly
	case "time.TimeOnly":
		return time.TimeOnly
	default:
		return fmt
	}
}
