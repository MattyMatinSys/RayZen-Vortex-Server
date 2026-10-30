// Shared server configuration helpers from the MIT-licensed StormDNS base.
package config

import "strings"

func defaultString(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func defaultIntBelow(value int, minValue int, fallback int) int {
	if value < minValue {
		return fallback
	}
	return value
}

func clampInt(value int, minValue int, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func defaultFloatAtMostZero(value float64, fallback float64) float64 {
	if value <= 0 {
		return fallback
	}
	return value
}

func defaultFloatBelow(value float64, minValue float64, fallback float64) float64 {
	if value < minValue {
		return fallback
	}
	return value
}

func clampFloat(value float64, minValue float64, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func serverConfigFlagName(tomlTag string) string {
	return strings.ToLower(strings.ReplaceAll(tomlTag, "_", "-"))
}
