package templates

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"text/template"
)

// ValidateTemplate validates a text template to result in valid JSON
// when it's executed with empty template data. If template execution
// results in invalid JSON, the template is invalid. When the template
// is valid, it can be used safely. A valid template can still in
// invalid JSON when non-empty template data is provided.
func ValidateTemplate(text string) error {
	failMessage := "fail"
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
			return fmt.Errorf("invalid JSON: %w", templatingError(err))
		}
	}

	return nil
}

// templatingError tries to extract more information about the cause of
// an error related to (most probably) malformed template data and adds
// this to the error message.
func templatingError(err error) error {
	var (
		syntaxError *json.SyntaxError
		typeError   *json.UnmarshalTypeError
	)
	// TODO(hs): extracting additional info doesn't always work as expected, as the provided template is
	// first transformed by executing it. After transformation, the offsets in the error are not the offsets
	// for the original template. If we want this to work, we should revert the transformation somehow and
	// then find the correct offset to use. This doesn't seem trivial to do.
	switch {
	case errors.As(err, &syntaxError):
		//return fmt.Errorf("%s at offset %d", err.Error(), syntaxError.Offset)
		return err
	case errors.As(err, &typeError):
		//return fmt.Errorf("cannot unmarshal %s at offset %d into Go value of type %s", typeError.Value, typeError.Offset, typeError.Type)
		return err
	default:
		return err
	}
}
