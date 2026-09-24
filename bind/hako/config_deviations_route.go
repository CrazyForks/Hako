package hako

import (
	"encoding/json"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/TokenPLS/Hako/hub/route"
)

func init() {
	route.Register(func(router chi.Router) {
		router.Get("/hako/v1/deviations", serveConfigDeviations)
	})
}

func serveConfigDeviations(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	payload := struct {
		SchemaVersion int                        `json:"schemaVersion"`
		Sequence      uint64                     `json:"sequence"`
		Entry         string                     `json:"entry,omitempty"`
		Document      *deviationDocumentIdentity `json:"document,omitempty"`
		Deviations    []configDeviation          `json:"deviations"`
	}{SchemaVersion: configDeviationSchemaVersion, Deviations: []configDeviation{}}
	if report := loadPublishedDeviationReport(); report != nil {
		payload.Sequence, payload.Entry = report.Sequence, report.Entry
		identity := report.Document
		payload.Document = &identity
		payload.Deviations = report.Deviations
	}
	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		http.Error(writer, "encode deviations", http.StatusInternalServerError)
	}
}
