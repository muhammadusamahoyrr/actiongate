package controlplane

import (
	"strings"
	"testing"
)

// Audit L4: Slack is all or nothing.
func TestValidateSlack(t *testing.T) {
	ok := []Config{
		{},
		{SlackBotToken: "xoxb", SlackSigningSecret: "s", SlackChannel: "C1"},
	}
	for _, c := range ok {
		if err := c.validateSlack(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := map[string]Config{
		"slack_signing_secret": {SlackBotToken: "xoxb", SlackChannel: "C1"},
		"slack_channel":        {SlackBotToken: "xoxb", SlackSigningSecret: "s"},
		"slack_bot_token":      {SlackSigningSecret: "s"},
	}
	for missing, c := range bad {
		err := c.validateSlack()
		if err == nil {
			t.Errorf("%+v: accepted, want %s reported missing", c, missing)
			continue
		}
		if _, after, _ := strings.Cut(err.Error(), " but "); !strings.Contains(after, missing) {
			t.Errorf("%+v: err = %v, want %s named as missing", c, err, missing)
		}
	}
}
