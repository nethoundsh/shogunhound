package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

func (h *ToolHandler) HandleShodanAlertCreate(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	name, ok := req.GetArguments()["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return mcp.NewToolResultError("missing required parameter: name"), nil
	}
	rawTargets, ok := req.GetArguments()["targets"].(string)
	if !ok || strings.TrimSpace(rawTargets) == "" {
		return mcp.NewToolResultError("missing required parameter: targets"), nil
	}

	targets := splitCSVOrLines(rawTargets)
	if len(targets) == 0 {
		return mcp.NewToolResultError("targets must contain at least one entry"), nil
	}
	if len(targets) > 100 {
		return mcp.NewToolResultError("targets must not exceed 100 entries"), nil
	}

	expires := 0
	switch v := req.GetArguments()["expires"].(type) {
	case float64:
		expires = int(v)
	case int:
		expires = v
	}

	alert, err := h.shodan.CreateAlert(ctx, strings.TrimSpace(name), targets, expires)
	if err != nil {
		h.logger.Error("alert_create_failed", "name", name, "targets", targets, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("alert_create", "name", name, "targets", targets, "alert_id", alert.ID, "success", true, "error", "")

	return mcp.NewToolResultText(fmt.Sprintf("Created alert %s (%s) for %d target(s)", alert.Name, alert.ID, len(alert.IPs))), nil
}

func (h *ToolHandler) HandleShodanAlertList(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	format, err := optionalString(req.GetArguments(), "format", "pretty")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	alerts, err := h.shodan.ListAlerts(ctx)
	if err != nil {
		h.logger.Error("alert_list_failed", "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("alert_list", "format", format, "count", len(alerts), "success", true, "error", "")

	switch format {
	case "json":
		out, jerr := json.MarshalIndent(alerts, "", " ")
		if jerr != nil {
			return mcp.NewToolResultError("failed to encode alerts"), nil
		}
		return mcp.NewToolResultText(string(out)), nil
	case "markdown":
		var b strings.Builder
		fmt.Fprintf(&b, "## Shodan Alerts\n\n")
		if len(alerts) == 0 {
			fmt.Fprintf(&b, "No alerts configured.\n")
			return mcp.NewToolResultText(b.String()), nil
		}
		fmt.Fprintf(&b, "| ID | Name | Targets | Expires |\n")
		fmt.Fprintf(&b, "|----|------|---------|---------|\n")
		for _, a := range alerts {
			if a == nil {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %d |\n", a.ID, a.Name, len(a.IPs), a.Expires)
		}
		return mcp.NewToolResultText(b.String()), nil
	default:
		var b strings.Builder
		if len(alerts) == 0 {
			return mcp.NewToolResultText("No alerts configured."), nil
		}
		fmt.Fprintf(&b, "SHODAN ALERTS (%d)\n", len(alerts))
		for _, a := range alerts {
			if a == nil {
				continue
			}
			fmt.Fprintf(&b, "- %s (%s) targets=%d expires=%d\n", a.Name, a.ID, len(a.IPs), a.Expires)
		}
		return mcp.NewToolResultText(strings.TrimSpace(b.String())), nil
	}
}

func (h *ToolHandler) HandleShodanAlertDelete(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	id, ok := req.GetArguments()["id"].(string)
	if !ok || strings.TrimSpace(id) == "" {
		return mcp.NewToolResultError("missing required parameter: id"), nil
	}

	if err := h.shodan.DeleteAlert(ctx, strings.TrimSpace(id)); err != nil {
		h.logger.Error("alert_delete_failed", "id", id, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("alert_delete", "id", strings.TrimSpace(id), "success", true, "error", "")
	return mcp.NewToolResultText("Alert deleted"), nil
}
