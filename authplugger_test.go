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
			authplugger cache_ttl 300
			authplugger remove_prefix /files
			authplugger allow_reading_parent_paths
			authplugger basicauth {
				user admin asdfasdf
				rw /

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
