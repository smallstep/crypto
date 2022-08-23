package templates

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"text/template"
)

// ValidateTemplate validates a text template results in valid JSON
// when it's executed with empty template data. If template execution
// results in invalid JSON, the template is invalid. When the template
// is valid, it can be used safely. A valid template can still result
// in invalid JSON when non-empty template data is provided.
func ValidateTemplate(text string) error {
	var failMessage string
	funcMap := GetFuncMap(&failMessage)

	// prepare the template with our template functions
	tmpl, err := template.New("template").Funcs(funcMap).Parse(text)
	if err != nil {
		return fmt.Errorf("error parsing template: %w", err)
	}

	// execute the template with empty data, resulting in nulls for fields
	// that aren't filled in the template
	buf := new(bytes.Buffer)
	if err := tmpl.Execute(buf, nil); err != nil {
		return fmt.Errorf("error validating template execution: %w", err)
	}

	// resulting JSON should be valid; if not, the template was not formatted correctly
	if ok := json.Valid(buf.Bytes()); !ok {
		// determine what's wrong with the JSON exactly; the `Valid` method doesn't return that
		var m map[string]interface{}
		if err := json.NewDecoder(buf).Decode(&m); err != nil {
			return fmt.Errorf("invalid JSON: %w", enrichJSONError(err))
		}

		// TODO(hs): json.Valid() returns NOK, but decoding doesn't result in error with trailing brace.
		// Results in `map[subject:<nil>]`. This is kind of a curious case to me. I think Valid() checks
		// the entire JSON; Decode() does not and sees the trailing brace as the final closing one, and
		// thus finishes the decoding. Shouldn't the behavior of the Decode be the same as Valid?
		return errors.New("invalid JSON: early decoder termination suspected")
	}

	return nil
}

// ValidateTemplateData validates that template data is
// valid JSON.
func ValidateTemplateData(text string) error {
	if ok := json.Valid([]byte(text)); !ok {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			return fmt.Errorf("invalid JSON: %w", enrichJSONError(err))
		}
	}

	return nil
}

// enrichJSONError tries to extract more information about the cause of
// an error related to a malformed JSON template and adds this to the
// error message.
func enrichJSONError(err error) error {
	var (
		syntaxError *json.SyntaxError
	)
	// TODO(hs): extracting additional info doesn't always work as expected, as the provided template is
	// first transformed by executing it. After transformation, the offsets in the error are not the offsets
	// for the original, user-provided template. If we want this to work, we should revert the transformation
	// somehow and then find the correct offset to use. This doesn't seem trivial to do.
	switch {
	case errors.As(err, &syntaxError):
		//return fmt.Errorf("%s at offset %d", err.Error(), syntaxError.Offset)
		return err
	default:
		return err
	}
}
