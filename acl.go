package auth

import "strings"

type access struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

func parseScope(sc string) *access {
	parts := strings.Split(sc, ":")
	if len(parts) < 3 || len(parts) > 4 {
		return nil
	}

	a := &access{Type: parts[0]}

	if len(parts) == 3 {
		a.Name = parts[1]
		a.Actions = strings.Split(parts[2], ",")
	} else {
		a.Name = parts[1] + ":" + parts[2]
		a.Actions = strings.Split(parts[3], ",")
	}

	return a
}
