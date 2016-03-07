package ultradns

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/parnurzeal/gorequest"
)

const (
	UltraHost = "https://restapi.ultradns.com"
	AuthURL = UltraHost + "/v1/authorization/token"
)

//type SearchParam struct {
//	Name     string
//	ZoneType string
//}

type VerInfo struct {
	Ver string `json:"version"`
}

type AccInfo struct {
	AccountName    string `json:"accountName"`
	AccountType    string `json:"accountType"`
	HolderUserName string `json:"accountHolderUserName"`
	OwnerUserName  string `json:"accountOwnerUserName"`
	NumUsers       string `json:"numberOfUsers"`
	NumGrps        string `json:"numberOfGroups"`
}

type QueryInfo struct {
	QSort   string `json:"sort,omitempty"`
	Reverse bool   `json:"reverse,omitempty"`
	Limit   int    `json:"limit"`
}

type ResultInfo struct {
	Total    int `json:"totalCount"`
	OffSet   int `json:"offset"`
	RetCount int `json:"returnedCount"`
}

type ZoneProp struct {
	ZName        string `json:"name"`
	AccName      string `json:"accountName"`
	AccType      string `json:"type"`
	DNSSecStatus string `json:"dnssecStatus"`
	Status       string `json:"status"`
	Owner        string `json:"owner"`
	RRCount      int    `json:"resourceRecordCount"`
	LastUpdated  string `json:"lastModifiedDateTime"`
}

type RegistrarInfo struct {
	Registrar    string `json:"registrar"`
	WhoIsExpires string `json:"whoisExpiration,omitempty"`
	NameServers  struct {
		             Ok        []string `json:"ok,omitempty"`
		             Unknown   []string `json:"unknown,omitempty"`
		             Missing   []string `json:"missing,omitempty"`
		             InCorrect []string `json:"incorrect,omitempty"`
	             } `json:"nameServers,omitempty"`
}

type Zone struct {
	Property    ZoneProp      `json:"properties"`
	RegInfo     RegistrarInfo `json:"registrarInfo"`
	RestrictIps []struct {
		SingleIP string `json:"singleIP,omitempty"`
		StartIP  string `json:"startIP,omitempty"`
		EndIP    string `json:"EndIP,omitempty"`
	} `json:"restrictIpList,omitempty"`
}

type RRSet struct {
	RecName  string   `json:"ownerName"`
	RType    string   `json:"rrtype"`
	TTL      int      `json:"ttl"`
	RRecords []string `json:"rdata"`
}

type AuthResp struct {
	TokenType    string `json:"tokenType"`
	RefreshToken string `json:"refreshToken"`
	AccessToken  string `json:"accessToken"`
	Expires      string `json:"expiresIn"`
	tokenType    string `json:"token_type"`
	refreshToken string `json:"refresh_token"`
	accessToken  string `json:"access_token"`
	expires      string `json:"expires_in"`
}

type UltraDns struct {
	userName     string
	password     string
	accessToken  string
	refreshToken string
	tokenHeader  string
	Client       *gorequest.SuperAgent
}

func NewSession() *UltraDns {
	return &UltraDns{
		userName:     "",
		password:     "",
		accessToken:  "",
		refreshToken: "",
		tokenHeader:  "",
		Client:       gorequest.New(),
	}
}

// get and set the authentication tokens
func (ud *UltraDns) Authenticate(username, password string) error {
	var authResp AuthResp
	payLoad := "grant_type=password&username=" + username + "&password=" + password

	resp, body, err := ud.Client.Post(AuthURL).Send(payLoad).End()
	if err != nil {
		return errors.New("Authentication Failed")
	}

	if resp.StatusCode != 200 {
		return errors.New("Something Bad Happened")
	}

	er := json.Unmarshal([]byte(body), &authResp)
	if er != nil {
		return errors.New("Unmarshal Error")
	}

	ud.accessToken = authResp.AccessToken
	ud.refreshToken = authResp.RefreshToken
	ud.tokenHeader = "Bearer " + ud.accessToken

	return nil
}

// get version
func (ud *UltraDns) GetVersion() (VerInfo, error) {
	var VInfo VerInfo

	_, body, err := ud.Client.Get(UltraHost + "/v1/version").End()
	if err != nil {
		return VInfo, errors.New("Authentication Failed")
	}

	errr := json.Unmarshal([]byte(body), &VInfo)
	if errr != nil {
		return VInfo, errors.New("Unmarshal Error")
	}

	return VInfo, nil
}

// get account details for user
func (ud *UltraDns) GetAccountDetails() ([]AccInfo, error) {
	var Res struct {
		RInfo    ResultInfo `json:"resultInfo"`
		Accounts []AccInfo  `json:"accounts"`
	}

	_, body, err := ud.Client.Get(UltraHost + "/v1/accounts").
	Set("Authorization", ud.tokenHeader).End()
	if err != nil {
		return Res.Accounts, errors.New("Authentication Failed")
	}

	errr := json.Unmarshal([]byte(body), &Res)
	if errr != nil {
		return Res.Accounts, errors.New("Unmarshal Error")
	}

	return Res.Accounts, nil
}

// list all zones for the account
func (ud *UltraDns) GetAllZones() ([]Zone, error) {
	var Res struct {
		QInfo QueryInfo  `json:"queryInfo"`
		RInfo ResultInfo `json:"resultInfo"`
		Zones []Zone     `json:"zones"`
	}

	_, body, err := ud.Client.Get(UltraHost + "/v1/zones").
	Set("Authorization", ud.tokenHeader).End()
	if err != nil {
		return Res.Zones, errors.New("Authentication Failed")
	}

	errr := json.Unmarshal([]byte(body), &Res)
	if errr != nil {
		return Res.Zones, errors.New("Unmarshal Error")
	}

	return Res.Zones, nil
}

// get all resource record sets
func (ud *UltraDns) GetRRsets(zName string, offset, limit int) ([]RRSet, ResultInfo, error) {
	var Res struct {
		ZName  string     `json:"zoneName"`
		QInfo  QueryInfo  `json:"queryInfo"`
		RInfo  ResultInfo `json:"resultInfo"`
		RRSets []RRSet    `json:"rrSets"`
	}

	_, body, err := ud.Client.Get(UltraHost + "/v1/zones/" + zName + "/rrsets").
	Query("offset=" + strconv.Itoa(offset)).
	Query("&limit=" + strconv.Itoa(limit)).
	Set("Authorization", ud.tokenHeader).End()
	if err != nil {
		return Res.RRSets, Res.RInfo, errors.New("Authentication Failed")
	}

	errr := json.Unmarshal([]byte(body), &Res)
	if errr != nil {
		return Res.RRSets, Res.RInfo, errors.New("Unmarshal Error")
	}

	return Res.RRSets, Res.RInfo, nil
}
