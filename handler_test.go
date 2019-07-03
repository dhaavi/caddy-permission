package permission

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/caddyserver/caddy"
)

var (
	testTimestamp = time.Now().Unix()
)

func TestConfigParsing(t *testing.T) {

	tests := []struct {
		input    string
		isValid  bool
		expected *Handler
	}{
		{
			`
			permission remove_prefix /files
			permission allow_reading_parent_paths
			permission basic {
				user admin password
				rw /secret/
				rw /internal/

				default
				ro /internal/

				public
				ro /
			}`,
			true,
			&Handler{
				Backends: []Backend{
					&BasicBackend{
						Users: map[string]string{
							"YWRtaW46cGFzc3dvcmQ=": "admin",
						},
						Permits: map[string]*Permit{
							"admin": &Permit{
								Rules: []*Rule{
									&Rule{
										Path: "/secret/",
										Methods: []string{
											"GET",
											"HEAD",
											"PROPFIND",
											"OPTIONS",
											"LOCK",
											"UNLOCK",
											"POST",
											"PUT",
											"DELETE",
											"MKCOL",
											"PROPPATCH",
										},
										MethodsAreBlacklist: false,
									},
									&Rule{
										Path: "/internal/",
										Methods: []string{
											"GET",
											"HEAD",
											"PROPFIND",
											"OPTIONS",
											"LOCK",
											"UNLOCK",
											"POST",
											"PUT",
											"DELETE",
											"MKCOL",
											"PROPPATCH",
										},
										MethodsAreBlacklist: false,
									},
								},
								ValidUntil: testTimestamp,
							},
						},
						DefaultPermit: &Permit{
							Rules: []*Rule{
								{
									Path: "/internal/",
									Methods: []string{
										"GET",
										"HEAD",
										"PROPFIND",
										"OPTIONS",
										"LOCK",
										"UNLOCK",
									},
									MethodsAreBlacklist: false,
								},
							},
							ValidUntil: testTimestamp,
						},
						PublicPermit: &Permit{
							Rules: []*Rule{
								{
									Path: "/",
									Methods: []string{
										"GET",
										"HEAD",
										"PROPFIND",
										"OPTIONS",
										"LOCK",
										"UNLOCK",
									},
									MethodsAreBlacklist: false,
								},
							},
							ValidUntil: testTimestamp,
						},
					},
				},
				ReadParentPath: true,
				RemovePrefix:   "/files",
			},
		},
	}

	for _, test := range tests {
		new, err := NewHandler(caddy.NewTestController("http", test.input), testTimestamp)
		if err != nil {
			t.Errorf("failed to create Handler: %s", err)
		}

		if !reflect.DeepEqual(new, test.expected) {
			newFormatted, err := json.MarshalIndent(new, "", "  ")
			if err != nil {
				t.Fatalf("failed for format Handler: %s", err)
				return
			}
			expectedFormatted, err := json.MarshalIndent(test.expected, "", "  ")
			if err != nil {
				t.Fatalf("failed for format Handler: %s", err)
				return
			}

			t.Errorf("unexpected Handler:\n===== got:\n%s\n===== expected:\n%s\n", newFormatted, expectedFormatted)
		}
	}

}

func TestConfigOptions(t *testing.T) {
	input := `
	permission remove_prefix /files
	permission allow_reading_parent_paths
	permission realm "Restricted Site"
	permission tls
	permission basic {
		user greg qwerty1 # This is greg, his password is qwerty1
		rw /tmp/ # he may read and write to /tmp/!

		user george # This is george, he does not have a password, another backend will have to authenticate him
		rw /admin/

		default # applies to all logged-in users
		rw /api/users/0 #

		public # applies to everyone, also anonymous users
		ro /static # everyone may read stuff in the static folder
		GET,HEAD /other
	}
	permission api {
		name MyWebsite # name of website
		user http://localhost:8080/caddyapi # main authentication api
		permit http://localhost:8080/caddyapi/{{username}} # refetch a permit of a user
		login http://localhost:8080/login?next={{resource}} # redirect here for logging in (resource is original URL)
		add_prefix /api/resource /files # add prefixes to returned paths
		add_without_prefix # if add_prefix is used, but you still want to also add the original paths
		cache 600 # how to long to cache authenticated users
		cleanup 3600 # when to clean out authenticated users
	}
	permission set_basicauth admin admin # set basic auth on forwarded request (ie use tls client certs as a front for a simple password based service)
	permission set_cookie token secret # set cookie on forwarded request
	permission set_cookie language en
	`
	_, err := NewHandler(caddy.NewTestController("http", input), testTimestamp)
	if err != nil {
		t.Errorf("failed to parse config: %s", err)
	}
}
