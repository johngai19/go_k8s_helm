package configloader

import (
	"fmt"
	"regexp"
)

// varSubstitutionRegex is precompiled for substituting ${VAR} or $VAR style variables.
// Group 1: Var name for ${VAR} (e.g., "VAR")
// Group 2: Preceding char for $VAR (e.g., " " in " $VAR", or empty if at start)
// Group 3: Var name for $VAR (e.g., "VAR")
var varSubstitutionRegex = regexp.MustCompile(`\$\{([^}]+)\}|(?:^|([^A-Za-z0-9_]))\$([A-Za-z_][A-Za-z0-9_]*)`)

// resolveValue attempts to substitute ${VAR} or $VAR style variables in a string.
// rawValue is the string containing potential variables.
// context provides the map of variables to use for substitution.
// It performs iterative substitution to handle multi-level dependencies (e.g., A=${B}, B=${C}).
func resolveValue(rawValue string, context map[string]string) string {
	resolvedValue := rawValue
	for i := 0; i < 10; i++ { // Limit iterations to prevent infinite loops from circular dependencies
		originalValue := resolvedValue
		resolvedValue = varSubstitutionRegex.ReplaceAllStringFunc(resolvedValue, func(foundMatch string) string {
			submatches := varSubstitutionRegex.FindStringSubmatch(foundMatch)
			var varName string
			var replacement string

			if submatches[1] != "" { // Matched ${VAR}
				varName = submatches[1]
				if val, ok := context[varName]; ok {
					replacement = val
				} else {
					replacement = foundMatch // Variable not in context
				}
			} else if submatches[3] != "" { // Matched $VAR
				varName = submatches[3]
				precedingChar := submatches[2]
				if val, ok := context[varName]; ok {
					replacement = precedingChar + val
				} else {
					replacement = foundMatch // Variable not in context
				}
			} else {
				replacement = foundMatch // Should not happen if regex matched
			}
			return replacement
		})

		if resolvedValue == originalValue { // No more substitutions made in this pass
			break
		}
		if i == 9 {
			// If still changing after many iterations, likely a circular dependency
			logWarning(fmt.Sprintf("Possible circular dependency or too deep recursion in variable resolution for: %s", rawValue))
		}
	}
	return resolvedValue
}

// resolveConfigMap resolves variables within a given configuration map (rawConfig).
// It uses a primaryContext (e.g., main resolved configurations) for external lookups,
// and the rawConfig itself for resolving internal references within the section.
// sectionName is used for logging purposes.
func resolveConfigMap(rawConfig map[string]string, primaryContext map[string]string, sectionName string, logPrefix string) map[string]string {
	resolvedConfig := make(map[string]string)
	if rawConfig == nil {
		return resolvedConfig
	}

	// Create a resolution context for variables in this rawConfig.
	// Variables from rawConfig itself take precedence over primaryContext for self-resolution.
	currentResolutionContext := make(map[string]string)
	for k, v := range primaryContext {
		currentResolutionContext[k] = v
	}
	for k, v := range rawConfig { // rawConfig values overlay primaryContext values
		currentResolutionContext[k] = v
	}

	for key, val := range rawConfig {
		resolvedVal := resolveValue(val, currentResolutionContext)
		resolvedConfig[key] = resolvedVal
		if val != resolvedVal {
			logMessage(fmt.Sprintf("%sResolved: Section='%s', Name='%s', RawValue='%s', ResolvedValue='%s'", logPrefix, sectionName, key, val, resolvedVal))
		}
	}
	return resolvedConfig
}
