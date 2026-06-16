// Package types holds the shared JSON response wrappers the frontend expects.
package types

// Re is the ajax response wrapper used by mutation endpoints (/doLogin,
// /notebook/addNotebook, /file/*, ...). Field names are PascalCase to match
// the original Revel JSON.
type Re struct {
	Ok   bool        `json:"Ok"`
	Code int         `json:"Code,omitempty"`
	Msg  string      `json:"Msg,omitempty"`
	Id   string      `json:"Id,omitempty"`
	List interface{} `json:"List,omitempty"`
	Item interface{} `json:"Item,omitempty"`
}

func OkRe() Re            { return Re{Ok: true} }
func OkItem(it any) Re    { return Re{Ok: true, Item: it} }
func OkId(id string) Re   { return Re{Ok: true, Id: id} }
func ErrRe(msg string) Re { return Re{Ok: false, Msg: msg} }

// Page mirrors info.Page; the frontend's PageList reads only Count and List.
type Page struct {
	CurPage     int         `json:"CurPage"`
	TotalPage   int         `json:"TotalPage"`
	PerPageSize int         `json:"PerPageSize"`
	Count       int         `json:"Count"`
	List        interface{} `json:"List"`
}

func NewPage(curPage, perPage, count int, list interface{}) Page {
	totalPage := 0
	if count > 0 && perPage > 0 {
		totalPage = (count + perPage - 1) / perPage
	}
	return Page{CurPage: curPage, TotalPage: totalPage, PerPageSize: perPage, Count: count, List: list}
}
