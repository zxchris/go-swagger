package models

import "github.com/go-swagger/go-swagger/strfmt"

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

/*Tag tag

swagger:model Tag
*/
type Tag struct {

	/* id
	 */
	ID int64 `json:"id,omitempty"`

	/* name
	 */
	Name string `json:"name,omitempty"`
}

// Validate validates this tag
func (m *Tag) Validate(formats strfmt.Registry) error {
	return nil
}
