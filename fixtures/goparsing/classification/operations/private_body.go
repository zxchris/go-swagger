package operations

// ActionParam for this thing
//
// swagger:parameters actionParam
type ActionParam struct {
	// in: body
	// required: true
	Body actionParam
}

type actionParam struct {
	// required: true
	FieldA string

	// required: true
	FieldB string

	// required: true
	FieldC int
}
