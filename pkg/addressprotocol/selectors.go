package addressprotocol

import (
	"fmt"
	"strings"
)

// SelectShapes applies the shared circuit_configs family/exact-key union rules.
// Empty configuration selects all shapes. Order and duplicate shapes are retained
// so callers can preserve independent deployment routes; manifests are not altered.
func SelectShapes(shapes []Shape, configured string) ([]Shape, error) {
	configured = strings.TrimSpace(configured)
	selectors := make(map[string]bool)
	for _, raw := range strings.Split(configured, ",") {
		if selector := strings.TrimSpace(raw); selector != "" {
			selectors[selector] = false
		}
	}
	if configured != "" && len(selectors) == 0 {
		return nil, fmt.Errorf("circuit_configs must select at least one native family or shape")
	}
	selected := make([]Shape, 0, len(shapes))
	for _, shape := range shapes {
		match := configured == ""
		for selector := range selectors {
			if selector == string(shape.Family) || selector == shape.Key() {
				selectors[selector], match = true, true
			}
		}
		if match {
			selected = append(selected, shape)
		}
	}
	for selector, matched := range selectors {
		if !matched {
			return nil, fmt.Errorf("circuit_configs selector %q matches no native family or shape in configured manifests; historical names are not supported", selector)
		}
	}
	return selected, nil
}
