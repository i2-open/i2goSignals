package httpSupport

import "net/http"

func HandleRespClose(resp *http.Response) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}
