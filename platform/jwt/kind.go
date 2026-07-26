package jwt

type Kind int

const (
	KindAccess Kind = iota
	KindRefresh
)
