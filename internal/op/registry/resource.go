package registry

import "slices"

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
				Scopes:     []string{"note.read", "note.write"},
			},
		},
	}
}

func (r *Resources) Audiences(scope string) []string {
	var ids []string
	for _, v := range r.resources {
		if slices.Contains(v.Scopes, scope) {
			ids = append(ids, v.Identifier)
		}
	}
	return ids
}
