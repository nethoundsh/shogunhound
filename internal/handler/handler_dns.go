package handler

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nethoundsh/shogunhound/internal/validator"
)

func (h *ToolHandler) HandleShodanDNSResolve(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	raw, err := requireString(req.GetArguments(), "hostnames")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	hostnames := splitAndTrim(raw)
	if len(hostnames) == 0 {
		return mcp.NewToolResultError("hostnames must contain at least one entry"), nil
	}
	if len(hostnames) > 100 {
		return mcp.NewToolResultError("hostnames must not exceed 100 entries"), nil
	}

	result, err := h.shodan.DNSResolve(ctx, hostnames)
	if err != nil {
		h.logger.Error("dns_resolve_failed", "hostnames", hostnames, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("dns_resolve", "hostnames", hostnames, "success", true, "error", "")

	var b strings.Builder
	for _, hostname := range hostnames {
		if ip, ok := result[hostname]; ok && ip != "" {
			fmt.Fprintf(&b, "%s -> %s\n", hostname, ip)
		} else {
			fmt.Fprintf(&b, "%s -> (not found)\n", hostname)
		}
	}

	return mcp.NewToolResultText(strings.TrimSpace(b.String())), nil
}

func (h *ToolHandler) HandleShodanDNSReverse(
	ctx context.Context,
	req mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	raw, err := requireString(req.GetArguments(), "ips")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	ips := splitAndTrim(raw)
	if len(ips) == 0 {
		return mcp.NewToolResultError("ips must contain at least one entry"), nil
	}
	if len(ips) > 100 {
		return mcp.NewToolResultError("ips must not exceed 100 entries"), nil
	}

	for _, ip := range ips {
		if err := validator.ValidateIP(ip); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("invalid IP %q: %s", ip, err.Error())), nil
		}
	}

	result, err := h.shodan.DNSReverse(ctx, ips)
	if err != nil {
		h.logger.Error("dns_reverse_failed", "ips", ips, "error", err.Error())
		return mcp.NewToolResultError(humanizeSearchError(err)), nil
	}
	h.logger.Info("dns_reverse", "ips", ips, "success", true, "error", "")

	var b strings.Builder
	for _, ip := range ips {
		if hostnames, ok := result[ip]; ok && len(hostnames) > 0 {
			fmt.Fprintf(&b, "%s -> %s\n", ip, strings.Join(hostnames, ", "))
		} else {
			fmt.Fprintf(&b, "%s -> (none)\n", ip)
		}
	}

	return mcp.NewToolResultText(strings.TrimSpace(b.String())), nil
}
