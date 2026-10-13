package registry

import (
	"slices"
	"strings"
)

type Resource struct {
	Identifier string
	Scopes     []string
}

type Resources struct {
	resources []Resource
}

func NewResource() *Resources {
	return &Resources{
		resources: []Resource{
			{
				Identifier: "http://localhost:9000",
				Scopes:     []string{"notes.read", "notes.write"},
			},
		},
	}
}

func (r *Resources) Audiences(scope string) []string {
	var ids []string
	sc := strings.Fields(scope)
	for _, v := range r.resources {
		if slices.ContainsFunc(sc, func(s string) bool {
			return slices.Contains(v.Scopes, s)
		}) {
			ids = append(ids, v.Identifier)
		}
	}
	return ids
}
