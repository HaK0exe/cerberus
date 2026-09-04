package mcp

import (
	"context"

	"github.com/HaK0exe/cerberus/internal/credentials"
	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// ListIncidentsTool implements cerberus_list_incidents.
type ListIncidentsTool struct {
	Store credentials.IncidentStore
}

func (t *ListIncidentsTool) Name() string               { return "cerberus_list_incidents" }
func (t *ListIncidentsTool) RequiredScopes() []Scope    { return []Scope{ScopeIncidentsRead} }
func (t *ListIncidentsTool) AllowedArguments() []string { return []string{"status", "limit"} }

func (t *ListIncidentsTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	filter := credentials.IncidentFilter{
		Status: cerberus.IncidentStatus(stringArg(args, "status")),
	}
	if v, ok := args["limit"]; ok {
		filter.Limit = intArg(v)
	}

	list, err := t.Store.ListIncidents(ctx, filter)
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Content: list}, nil
}

// GetIncidentTool implements cerberus_get_incident.
type GetIncidentTool struct {
	Store credentials.IncidentStore
}

func (t *GetIncidentTool) Name() string               { return "cerberus_get_incident" }
func (t *GetIncidentTool) RequiredScopes() []Scope    { return []Scope{ScopeIncidentsRead} }
func (t *GetIncidentTool) AllowedArguments() []string { return []string{"incident_id"} }

func (t *GetIncidentTool) Handle(ctx context.Context, args map[string]any) (ToolResult, error) {
	id := stringArg(args, "incident_id")
	if id == "" {
		return ToolResult{IsError: true, ErrorMessage: "incident_id is required"}, nil
	}
	i, err := t.Store.GetIncident(ctx, id)
	if err != nil {
		return ToolResult{IsError: true, ErrorMessage: err.Error()}, nil
	}
	return ToolResult{Content: i}, nil
}
