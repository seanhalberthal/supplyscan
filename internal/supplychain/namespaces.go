package supplychain

import (
	"slices"
	"strings"
)

// atRiskNamespaces contains npm scopes that have had compromised packages.
// Packages from these namespaces trigger warnings even if the installed
// version appears safe.
var atRiskNamespaces = []string{
	// Shai-Hulud campaign (September-November 2025)
	"@ctrl",
	"@nativescript-community",
	"@crowdstrike",
	"@asyncapi",
	"@posthog",
	"@postman",
	"@ensdomains",
	"@zapier",
	"@art-ws",
	"@ngx",
	// s1ngularity campaign (August 2025) — credential harvesting via Nx build system
	"@nx",
	"@nrwl",
	// Mini Shai-Hulud / TeamPCP campaign (April-May 2026) — self-spreading worm targeting
	// SAP CAP, TanStack, AntV, and other npm scopes
	"@cap-js",
	"@tanstack",
	"@antv",
	"@lint-md",
	"@openclaw-cn",
	"@starmind",
}

// isAtRiskNamespace checks if a package name belongs to an at-risk namespace.
func isAtRiskNamespace(packageName string) bool {
	if !strings.HasPrefix(packageName, "@") {
		return false
	}

	// Extract the scope (e.g., "@ctrl" from "@ctrl/tinycolor")
	before, _, ok := strings.Cut(packageName, "/")
	if !ok {
		return false
	}

	scope := before
	return slices.Contains(atRiskNamespaces, scope)
}

// getNamespaceWarning returns a warning message for an at-risk namespace.
func getNamespaceWarning(packageName string) string {
	return "Namespace '" + packageName + "' had compromised packages in a supply chain attack. This version appears safe but verify."
}
