package pservice

type Service struct {
	Endpoints []Endpoint
	BasicEndpoint Endpoint 
	Active bool
	Name string
	HeaderReplace []HeaderReplace
}

type Endpoint struct {
	Endpoint string
	VerifySSL bool
	Active bool
	Name string
	HeaderMatches []HeaderMatch
}

type HeaderMatch struct {
	Header string
	Value string
}

type HeaderReplace struct {
	Header string
	Value string
	NewValue string
}