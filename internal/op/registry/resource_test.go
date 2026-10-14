package registry

import (
	"reflect"
	"testing"
)

func TestResources_Audiences(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  []string
	}{
		{"scope が openid だけの場合、nil が返る", "openid", nil},
		{"scope が openid notes.read の場合、RS の URL が返る", "openid notes.read", []string{"http://localhost:9000"}},
		{"scope が openid notes.write の場合、RS の URL が返る", "openid notes.write", []string{"http://localhost:9000"}},
		{"scope が openid notes.read notes.write の場合、RS の URL が返る", "openid notes.read notes.write", []string{"http://localhost:9000"}},
		{"scope が空文字の場合", "", nil},
		{"scope が前方一致の場合", "openid notes", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewResources()
			got := r.Audiences(tt.scope)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindBySub() = %v, want %v", got, tt.want)
			}
		})
	}
}
