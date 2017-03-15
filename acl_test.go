package dockerauth

import (
	"net/http"
	"testing"
)

var scopeTests = []struct {
	test   string
	access *access
}{
	{
		test:   "repository:pull,push",
		access: nil,
	},
	{
		test: "repository:alpine:pull",
		access: &access{
			Type:    "repository",
			Name:    "alpine",
			Actions: []string{"pull"},
		},
	},
	{
		test: "repository:test/image:pull,push",
		access: &access{
			Type:    "repository",
			Name:    "test/image",
			Actions: []string{"pull", "push"},
		},
	},
	{
		test: "repository:example.com:5000/test/image:pull,push",
		access: &access{
			Type:    "repository",
			Name:    "example.com:5000/test/image",
			Actions: []string{"pull", "push"},
		},
	},
}

func TestScopeParse(t *testing.T) {
	for _, testCase := range scopeTests {
		a := parseScope(testCase.test)
		equals(t, a, testCase.access)
	}
}

var actionListTests = []struct {
	init     []string
	equal    *actionList
	expected []string
}{
	{
		init:     []string{},
		equal:    &actionList{},
		expected: []string{},
	},
	{
		init:     []string{"pull"},
		equal:    &actionList{pull: true},
		expected: []string{"pull"},
	},
	{
		init:     []string{"something"},
		equal:    &actionList{},
		expected: []string{},
	},
	{
		init:     []string{"pull", "push"},
		equal:    &actionList{pull: true, push: true},
		expected: []string{"pull", "push"},
	},
	{
		init:     []string{"push", "pull"},
		equal:    &actionList{pull: true, push: true},
		expected: []string{"pull", "push"},
	},
	{
		init:     []string{"pull", "push", "delete", "catalog"},
		equal:    &actionList{pull: true, push: true, delete: true, catalog: true},
		expected: []string{"pull", "push", "delete", "catalog"},
	},
}

func TestActionList(t *testing.T) {
	for _, test := range actionListTests {
		al := newActionList(test.init)
		equals(t, al, test.equal)
		equals(t, al.toSlice(), test.expected)
	}
}

var actionListAddTests = []struct {
	init     []string
	add      []string
	expected *actionList
}{
	{
		init:     []string{},
		add:      []string{},
		expected: &actionList{},
	},
	{
		init:     []string{"pull"},
		add:      []string{},
		expected: &actionList{pull: true},
	},
	{
		init:     []string{},
		add:      []string{"push"},
		expected: &actionList{push: true},
	},
	{
		init:     []string{"pull"},
		add:      []string{"push"},
		expected: &actionList{pull: true, push: true},
	},
	{
		init:     []string{"push"},
		add:      []string{"delete", "catalog"},
		expected: &actionList{push: true, delete: true, catalog: true},
	},
}

func TestActionListAddSlice(t *testing.T) {
	for _, test := range actionListAddTests {
		al := newActionList(test.init)
		al.addSlice(test.add)
		equals(t, al, test.expected)
	}
}

func TestActionListAdd(t *testing.T) {
	for _, test := range actionListAddTests {
		al := newActionList(test.init)
		for _, action := range test.add {
			al.add(action)
		}
		equals(t, al, test.expected)
	}
}

var actionListIntersectionTests = []struct {
	a1        *actionList
	a2        *actionList
	intersect *actionList
}{
	{
		a1:        &actionList{},
		a2:        &actionList{},
		intersect: &actionList{},
	},
	{
		a1:        &actionList{push: true},
		a2:        &actionList{},
		intersect: &actionList{},
	},
	{
		a1:        &actionList{},
		a2:        &actionList{push: true},
		intersect: &actionList{},
	},
	{
		a1:        &actionList{push: true},
		a2:        &actionList{pull: true, push: true},
		intersect: &actionList{push: true},
	},
	{
		a1:        &actionList{push: true, delete: true},
		a2:        &actionList{pull: true, push: true, delete: true},
		intersect: &actionList{push: true, delete: true},
	},
}

func TestActionListIntersect(t *testing.T) {
	for _, test := range actionListIntersectionTests {
		al := test.a1.intersect(test.a2)
		equals(t, al, test.intersect)
	}
}

var aclFilterTests = []struct {
	start    []*AccessControl
	repo     string
	expected []*AccessControl
}{
	{
		start: []*AccessControl{
			{Repository: "alpine"},
			{Repository: "namespace/project"},
		},
		repo: "alpine",
		expected: []*AccessControl{
			{Repository: "alpine"},
		},
	},
	{
		start: []*AccessControl{
			{Repository: "alpine"},
			{Repository: "namespace/project"},
		},
		repo: "namespace/project",
		expected: []*AccessControl{
			{Repository: "namespace/project"},
		},
	},
	{
		start: []*AccessControl{
			{Repository: "alpine"},
			{Repository: "namespace/project"},
			{Repository: "namespace/*"},
		},
		repo: "namespace/project",
		expected: []*AccessControl{
			{Repository: "namespace/project"},
			{Repository: "namespace/*"},
		},
	},
	{
		start: []*AccessControl{
			{Repository: "alpine"},
			{Repository: "*"},
		},
		repo:     "namespace/project",
		expected: []*AccessControl{},
	},
	{
		start: []*AccessControl{
			{Repository: "alpine"},
			{Repository: "**"},
		},
		repo: "namespace/project",
		expected: []*AccessControl{
			{Repository: "**"},
		},
	},
}

func TestACLRepoFilter(t *testing.T) {
	a := &Authenticator{}

	for _, test := range aclFilterTests {
		f := a.filterRepository(test.start, test.repo)
		equals(t, f, test.expected)
	}
}

var checkIPTests = []struct {
	ip       string
	acls     []*AccessControl
	expected bool
}{
	{
		ip: "127.0.0.1",
		acls: []*AccessControl{
			&AccessControl{IP: "*"},
		},
		expected: true,
	},
	{
		ip: "127.0.0.1",
		acls: []*AccessControl{
			&AccessControl{IP: "127.0.0.*"},
		},
		expected: true,
	},
	{
		ip: "128.0.0.1",
		acls: []*AccessControl{
			&AccessControl{IP: "127.0.0.*"},
		},
		expected: false,
	},
}

func TestACLIPFilter(t *testing.T) {
	a := &Authenticator{}

	for _, test := range checkIPTests {
		r, _ := http.NewRequest("", "", nil)
		r.RemoteAddr = test.ip

		check := a.checkIPAddress(r, test.acls)
		assert(t, check == test.expected,
			"IP address check error. Got %t, expected %t",
			check, test.expected)
	}
}

func TestACLIPFilterHeader(t *testing.T) {
	a := &Authenticator{}

	for _, test := range checkIPTests {
		r, _ := http.NewRequest("", "", nil)
		r.Header.Set(http.CanonicalHeaderKey("X-Real-IP"), test.ip)

		check := a.checkIPAddress(r, test.acls)
		assert(t, check == test.expected,
			"IP address check error. Got %t, expected %t",
			check, test.expected)
	}
}

var aclCompareTests = []struct {
	acls   []*AccessControl
	req    *access
	result *access
}{
	{
		acls:   nil,
		req:    &access{Actions: []string{"push"}},
		result: &access{Actions: []string{}},
	},
	{
		acls:   []*AccessControl{},
		req:    &access{Actions: []string{"push"}},
		result: &access{Actions: []string{}},
	},
	{
		acls: []*AccessControl{
			&AccessControl{Actions: []string{"push"}},
		},
		req:    &access{Actions: []string{"push"}},
		result: &access{Actions: []string{"push"}},
	},
	{
		acls: []*AccessControl{
			&AccessControl{Actions: []string{"pull", "push"}},
		},
		req:    &access{Actions: []string{"push"}},
		result: &access{Actions: []string{"push"}},
	},
	{
		acls: []*AccessControl{
			&AccessControl{Actions: []string{"push"}},
		},
		req:    &access{Actions: []string{"pull", "push"}},
		result: &access{Actions: []string{"push"}},
	},
	{
		acls: []*AccessControl{
			&AccessControl{Actions: []string{"pull", "push"}},
		},
		req:    &access{Actions: []string{"pull", "push"}},
		result: &access{Actions: []string{"pull", "push"}},
	},
	{
		acls: []*AccessControl{
			&AccessControl{Actions: []string{"pull"}},
			&AccessControl{Actions: []string{"push"}},
		},
		req:    &access{Actions: []string{"pull", "push"}},
		result: &access{Actions: []string{"pull", "push"}},
	},
	{
		acls: []*AccessControl{
			&AccessControl{Actions: []string{"pull"}},
			&AccessControl{Actions: []string{"pull"}},
		},
		req:    &access{Actions: []string{"pull", "push"}},
		result: &access{Actions: []string{"pull"}},
	},
}

func TestCompareACLs(t *testing.T) {
	a := &Authenticator{}

	for _, test := range aclCompareTests {
		res := a.compareACLS(test.acls, test.req)
		equals(t, res, test.result)
	}
}
