package authplugger

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mholt/caddy"
)

func TestConfigParsing(t *testing.T) {

	tests := []struct {
		input     string
		shouldErr bool
		expected  *AuthPlugger
	}{
		{
			`
			authplugger remove_prefix /files
			authplugger allow_reading_parent_paths
			authplugger basic {
				user admin asdfasdf
				rw /secret/
				rw /internal/

				*
				ro /internal/

				!
				ro /
			}`,
			false,
			&AuthPlugger{},
		},
	}

	for _, test := range tests {
		new, err := NewAuthPlugger(caddy.NewTestController("http", test.input))
		if err != nil {
			t.Errorf("failed to create AuthPlugger: %s", err)
		}

		b, err := json.MarshalIndent(new, "", "  ")
		if err != nil {
			fmt.Printf("could not format AuthPlugger: %s", err)
		}
		fmt.Println(string(b))

	}

}
