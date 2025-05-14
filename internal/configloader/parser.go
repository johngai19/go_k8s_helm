package configloader

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// parseConfFile reads a .conf file and returns a map of key-value pairs.
// It updates the provided 'targetConfig' map. If a key already exists, it's overwritten,
// and a warning is logged.
// filePath is the path to the configuration file.
// targetConfig is the map to populate/update with parsed variables.
// sectionName is a logical name for the source of these variables (e.g., "MAIN", "DB_MYSQL"), used for logging.
// logPrefix is a prefix for log messages, useful for distinguishing parsing stages.
func parseConfFile(filePath string, targetConfig map[string]string, sectionName string, logPrefix string) error {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			logWarning(fmt.Sprintf("%sConfiguration file '%s' not found. Skipping.", logPrefix, filePath))
			return nil // Not an error to skip a non-existent optional file
		}
		return fmt.Errorf("%sfailed to open file %s: %w", logPrefix, filePath, err)
	}
	defer file.Close()

	logMessage(fmt.Sprintf("%sParsing %s variables from: %s", logPrefix, sectionName, filePath))
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		originalLine := scanner.Text()
		trimmedLine := strings.TrimSpace(originalLine)

		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue // Skip empty lines and full-line comments
		}

		parts := strings.SplitN(trimmedLine, "=", 2)
		key := strings.TrimSpace(parts[0])
		var value string

		if len(parts) == 2 {
			rawValuePart := parts[1] // Segment after the first '='
			parsedAsQuoted := false
			valueCandidate := strings.TrimSpace(rawValuePart) // Trim spaces to check for quotes accurately

			if len(valueCandidate) >= 2 {
				firstChar := valueCandidate[0]
				lastChar := valueCandidate[len(valueCandidate)-1]
				if (firstChar == '"' && lastChar == '"') || (firstChar == '\'' && lastChar == '\'') {
					value = valueCandidate[1 : len(valueCandidate)-1] // Remove the quotes
					parsedAsQuoted = true
				}
			}

			if !parsedAsQuoted {
				effectiveValuePart := rawValuePart // Start with segment after '='
				commentIndex := strings.IndexByte(effectiveValuePart, '#')
				if commentIndex != -1 {
					effectiveValuePart = effectiveValuePart[:commentIndex] // Remove comment
				}
				// For unquoted values, value ends at the first whitespace or end of string (after comment removal)
				spaceIndex := strings.IndexByte(effectiveValuePart, ' ')
				if spaceIndex != -1 {
					effectiveValuePart = effectiveValuePart[:spaceIndex] // Value is before the first space
				}
				value = strings.TrimSpace(effectiveValuePart) // Trim any remaining spaces
			}
		} else {
			// No "=" found after key, or key without value. Treat value as empty.
			value = ""
		}

		if existingVal, ok := targetConfig[key]; ok {
			logWarning(fmt.Sprintf("%sLine %d: Variable '%s' in '%s' (new value: '%s') overwrites previous value '%s'.", logPrefix, lineNumber, key, filePath, value, existingVal))
		}
		targetConfig[key] = value
		logMessage(fmt.Sprintf("%sFound Raw: Path='%s', Line=%d, Section='%s', Name='%s', Value='%s'", logPrefix, filePath, lineNumber, sectionName, key, value))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%serror scanning file %s: %w", logPrefix, filePath, err)
	}
	return nil
}
