package mcp

import (
	"context"

	"github.com/HaK0exe/cerberus/internal/credentials"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// ListCredentialsTool implements cerberus_list_credentials.
type ListCredentialsTool struct {
	Store credentials.CredentialStore
}

func (t *ListCredentialsTool) Name() string            { return "cerberus_list_credentials" }
func (t *ListCredentialsTool) RequiredScopes() []Scope { return []Scope{ScopeCredentialsRead} }
func (t *ListCredentialsTool) AllowedArguments() []string {
	return []string{"provider", "status", "limit"}
}

func (t *ListCredentialsTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	filter := credentials.CredentialFilter{
		Provider: stringArg(args, "provider"),
		Status:   cerberus.CredentialStatus(stringArg(args, "status")),
	}
	if v, ok := args["limit"]; ok {
		filter.Limit = intArg(v)
	}

	list, err := t.Store.List(ctx, filter)
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Content: list}, nil
}

// GetCredentialTool implements cerberus_get_credential.
type GetCredentialTool struct {
	Store credentials.CredentialStore
}

func (t *GetCredentialTool) Name() string               { return "cerberus_get_credential" }
func (t *GetCredentialTool) RequiredScopes() []Scope    { return []Scope{ScopeCredentialsRead} }
func (t *GetCredentialTool) AllowedArguments() []string { return []string{"credential_id"} }

func (t *GetCredentialTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	id := stringArg(args, "credential_id")
	if id == "" {
		return ToolResult{IsError: true, ErrorMessage: "credential_id is required"}, nil
	}
	c, err := t.Store.Get(ctx, id)
	if err != nil {
		return ToolResult{IsError: true, ErrorMessage: err.Error()}, nil
	}
	return ToolResult{Content: c}, nil
}
