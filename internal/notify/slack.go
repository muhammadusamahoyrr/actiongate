package notify

import (
	"context"
	"fmt"

	"github.com/slack-go/slack"
)

// SlackPort delivers approval requests as Slack messages with Approve/Deny
// buttons. Delivery only (plan §14): the buttons carry the opaque callback
// token, and the decision flows back through the control plane's
// /slack/interaction endpoint — this port never decides anything.
type SlackPort struct {
	Client *slack.Client
	// Channels routes approver targets (plan §9: "financial" → finance
	// on-call) to Slack channel IDs; DefaultChannel catches the rest.
	Channels       map[string]string
	DefaultChannel string
}

func (p SlackPort) Send(ctx context.Context, msg Message) error {
	channel := p.Channels[msg.ApproverTarget]
	if channel == "" {
		channel = p.DefaultChannel
	}
	if channel == "" {
		return fmt.Errorf("no slack channel for approver target %q and no default", msg.ApproverTarget)
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, msg.Title, false, false)),
		slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, msg.Body, false, false), nil, nil),
		slack.NewContextBlock("",
			slack.NewTextBlockObject(slack.MarkdownType,
				fmt.Sprintf("action `%s` · approver `%s`", msg.ActionID, msg.ApproverTarget), false, false)),
		slack.NewActionBlock("actiongate_approval",
			&slack.ButtonBlockElement{
				Type: slack.METButton, ActionID: "approve", Value: msg.CallbackToken,
				Text:  slack.NewTextBlockObject(slack.PlainTextType, "Approve", false, false),
				Style: slack.StylePrimary,
			},
			&slack.ButtonBlockElement{
				Type: slack.METButton, ActionID: "deny", Value: msg.CallbackToken,
				Text:  slack.NewTextBlockObject(slack.PlainTextType, "Deny", false, false),
				Style: slack.StyleDanger,
			},
		),
	}
	_, _, err := p.Client.PostMessageContext(ctx, channel, slack.MsgOptionBlocks(blocks...))
	if err != nil {
		return fmt.Errorf("slack post to %s: %w", channel, err)
	}
	return nil
}
