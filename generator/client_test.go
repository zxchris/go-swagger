package generator

import (
	"bytes"
	"testing"

	"github.com/go-swagger/go-swagger/spec"
	"github.com/stretchr/testify/assert"
)

func TestGenerateClient_Issue320(t *testing.T) {
	specDoc, err := spec.Load("../fixtures/codegen/todolist.simple.yml")
	if assert.NoError(t, err) {
		method, path, op, ok := specDoc.OperationForName("CreateServiceFiles")
		if assert.True(t, ok) {
			bldr := codeGenOpBuilder{
				Name:          "CreateServiceFiles",
				Method:        method,
				Path:          path,
				APIPackage:    "restapi",
				ModelsPackage: "models",
				Principal:     "",
				Target:        ".",
				Doc:           specDoc,
				Operation:     *op,
				Authed:        false,
				DefaultScheme: "http",
				ExtraSchemas:  make(map[string]GenSchema),
			}
			genOp, err := bldr.MakeOperation()
			if assert.NoError(t, err) {
				var buf bytes.Buffer
				err := clientParamTemplate.Execute(&buf, genOp)
				if assert.NoError(t, err) {
					res := buf.String()
					assertInCode(t, "r.SetFileParam(\"files\", &o.Files)", res)
					assertNotInCode(t, "o.Files != nil", res)
					assertInCode(t, "r.SetFileParam(\"optionalFile\", o.OptionalFile)", res)
					assertInCode(t, "o.OptionalFile != nil", res)
				}
			}
		}
	}
}
