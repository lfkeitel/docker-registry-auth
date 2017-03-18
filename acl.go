package dockerauth

import (
	"net/http"
	"strings"
)

type actionList struct {
	pull, push, star bool
}

func newActionList(actions []string) *actionList {
	a := &actionList{}
	a.addSlice(actions)
	return a
}

func (a *actionList) add(action string) {
	switch action {
	case "pull":
		a.pull = true
	case "push":
		a.push = true
	case "*":
		a.star = true
	}
}

func (a *actionList) addSlice(actions []string) {
	for _, action := range actions {
		a.add(action)
	}
}

func (a *actionList) toSlice() []string {
	actions := []string{}
	if a.pull {
		actions = append(actions, "pull")
	}
	if a.push {
		actions = append(actions, "push")
	}
	if a.star {
		actions = append(actions, "*")
	}
	return actions
}

func (a *actionList) intersect(a2 *actionList) *actionList {
	return &actionList{
		pull: a.pull && a2.pull,
		push: a.push && a2.push,
		star: a.star && a2.star,
	}
}

type AccessControl struct {
	IP      string   `json:"-"`
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

func parseScope(sc string) *AccessControl {
	parts := strings.Split(sc, ":")
	if len(parts) < 3 || len(parts) > 4 {
		return nil
	}

	a := &AccessControl{Type: parts[0]}

	if len(parts) == 3 {
		a.Name = parts[1]
		a.Actions = strings.Split(parts[2], ",")
	} else {
		a.Name = parts[1] + ":" + parts[2]
		a.Actions = strings.Split(parts[3], ",")
	}

	return a
}

func (a *Authenticator) filterRepository(acls []*AccessControl, repo string) []*AccessControl {
	var newAcls []*AccessControl
	for _, acl := range acls {
		if globMatch(acl.Name, repo) {
			newAcls = append(newAcls, acl)
		}
	}

	if newAcls == nil {
		newAcls = make([]*AccessControl, 0)
	}
	return newAcls
}

func (a *Authenticator) checkIPAddress(r *http.Request, acls []*AccessControl) bool {
	ip := r.RemoteAddr
	if realIP := r.Header.Get(http.CanonicalHeaderKey("X-Real-IP")); realIP != "" {
		ip = strings.SplitAfterN(realIP, ":", 2)[0]
	}

	for _, acl := range acls {
		if !globMatch(acl.IP, ip) {
			return false
		}
	}
	return true
}

func (a *Authenticator) compareACLS(acls []*AccessControl, req *AccessControl) *AccessControl {
	if acls == nil || len(acls) == 0 {
		return &AccessControl{
			Type:    req.Type,
			Name:    req.Name,
			Actions: []string{},
		}
	}

	reqActions := newActionList(req.Actions)
	allowedActions := newActionList(nil)
	for _, acl := range acls {
		allowedActions.addSlice(acl.Actions)
	}

	return &AccessControl{
		Type:    req.Type,
		Name:    req.Name,
		Actions: allowedActions.intersect(reqActions).toSlice(),
	}
}
