package response

// @Description Стандартный ответ API
type Response struct {
	Status string `json:"status" example:"OK"`
	Error  string `json:"error,omitempty" example:"something went wrong"`
}

const (
	StatusOK    = "OK"
	StatusError = "Error"
)

func Error(msg string) Response {
	return Response{
		Status: StatusError,
		Error:  msg,
	}
}
