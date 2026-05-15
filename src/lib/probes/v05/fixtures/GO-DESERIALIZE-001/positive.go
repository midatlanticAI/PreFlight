// XL-001 / GO-DESERIALIZE-001 positive fixture.
// Decoding the request body with no MaxBytesReader bound.
package handlers

func Handle(w http.ResponseWriter, r *http.Request) {
	var v Payload
	json.NewDecoder(r.Body).Decode(&v)
	use(v)
}
