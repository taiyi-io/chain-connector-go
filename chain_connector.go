package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	json "github.com/json-iterator/go"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

type ContractInfo struct {
	Name         string `json:"name"`
	Version      int    `json:"version"`
	ModifiedTime string `json:"modified_time"`
	Enabled      bool   `json:"enabled"`
	Trace        bool   `json:"trace,omitempty"`
}

type PropertyType string

const (
	PropertyTypeString     = "string"
	PropertyTypeBoolean    = "bool"
	PropertyTypeInteger    = "int"
	PropertyTypeFloat      = "float"
	PropertyTypeCurrency   = "currency"
	PropertyTypeCollection = "collection"
	PropertyTypeDocument   = "document"
)

const (
	defaultProjectName            = "Taiyi"
	SDKVersion                    = "0.2.1"
	ApiVersion                    = 1
	DefaultDomainName             = "system"
	DefaultDomainHost             = "localhost"
	DefaultMaxConnections         = 100
	DefaultClientTimeoutInSeconds = 10
)

type DocumentProperty struct {
	Name    string       `json:"name"`
	Type    PropertyType `json:"type"`
	Indexed bool         `json:"indexed,omitempty"`
}

type DocumentSchema struct {
	Name       string             `json:"name"`
	Properties []DocumentProperty `json:"properties,omitempty"`
}

type Document struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

type FilterOperatorType int

const (
	FilterOperatorEQ FilterOperatorType = iota //equal
	FilterOperatorNE                           //not equal
	FilterOperatorGT                           //greater than
	FilterOperatorLT                           //lesser than
	FilterOperatorGE                           //greater or equal
	FilterOperatorLE                           //lesser or equal
	FilterOperatorInvalid
)

type ConditionFilter struct {
	Property string             `json:"property"`
	Operator FilterOperatorType `json:"operator"`
	Value    string             `json:"value"`
}

type QueryCondition struct {
	Filters []ConditionFilter `json:"filters,omitempty"`
	Since   string            `json:"since,omitempty"`
	Offset  int               `json:"offset,omitempty"`
	Limit   int               `json:"limit,omitempty"`
	Order   string            `json:"order,omitempty"`
	Descend bool              `json:"descend,omitempty"`
}

func (condition *QueryCondition) PropertyEqual(propertyName, value string) *QueryCondition {
	condition.Filters = append(condition.Filters, ConditionFilter{
		Property: propertyName,
		Operator: FilterOperatorEQ,
		Value:    value,
	})
	return condition
}

func (condition *QueryCondition) PropertyNotEqual(propertyName, value string) *QueryCondition {
	condition.Filters = append(condition.Filters, ConditionFilter{
		Property: propertyName,
		Operator: FilterOperatorNE,
		Value:    value,
	})
	return condition
}

func (condition *QueryCondition) PropertyGreaterThan(propertyName, value string) *QueryCondition {
	condition.Filters = append(condition.Filters, ConditionFilter{
		Property: propertyName,
		Operator: FilterOperatorGT,
		Value:    value,
	})
	return condition
}

func (condition *QueryCondition) PropertyLessThan(propertyName, value string) *QueryCondition {
	condition.Filters = append(condition.Filters, ConditionFilter{
		Property: propertyName,
		Operator: FilterOperatorLT,
		Value:    value,
	})
	return condition
}

func (condition *QueryCondition) PropertyGreaterOrEqual(propertyName, value string) *QueryCondition {
	condition.Filters = append(condition.Filters, ConditionFilter{
		Property: propertyName,
		Operator: FilterOperatorGE,
		Value:    value,
	})
	return condition
}

func (condition *QueryCondition) PropertyLessOrEqual(propertyName, value string) *QueryCondition {
	condition.Filters = append(condition.Filters, ConditionFilter{
		Property: propertyName,
		Operator: FilterOperatorLE,
		Value:    value,
	})
	return condition
}

func (condition *QueryCondition) StartFrom(value string) *QueryCondition {
	condition.Since = value
	return condition
}

func (condition *QueryCondition) SetOffset(offset int) *QueryCondition {
	condition.Offset = offset
	return condition
}

func (condition *QueryCondition) MaxRecord(limit int) *QueryCondition {
	condition.Limit = limit
	return condition
}

func (condition *QueryCondition) AscendBy(property string) *QueryCondition {
	condition.Order = property
	return condition
}

func (condition *QueryCondition) DescendBy(property string) *QueryCondition {
	condition.Order = property
	condition.Descend = true
	return condition
}

func (condition *QueryCondition) Marshal() (content string, err error) {
	content, err = json.MarshalToString(condition)
	return
}

func (condition *QueryCondition) Unmarshal(content string) (err error) {
	err = json.UnmarshalFromString(content, condition)
	return
}

type TraceLog struct {
	Version     uint64 `json:"version"`
	Timestamp   string `json:"timestamp"`
	Operate     string `json:"operate"`
	Invoker     string `json:"invoker"`
	Block       string `json:"block,omitempty"`
	Transaction string `json:"transaction,omitempty"`
	Confirmed   bool   `json:"confirmed"`
}

type ContractStep struct {
	Action string   `json:"action"`
	Params []string `json:"params,omitempty"`
}

type BlockData struct {
	ID            string `json:"id"`
	Timestamp     string `json:"timestamp"`
	PreviousBlock string `json:"previous_block"`
	Height        uint64 `json:"height"`
	Transactions  int    `json:"transactions"`
	Content       string `json:"content"`
}

type TransactionData struct {
	Block       string `json:"block"`
	Transaction string `json:"transaction"`
	Timestamp   string `json:"timestamp"`
	Validated   bool   `json:"validated"`
	Content     string `json:"content"`
}

type ContractDefine struct {
	Steps []ContractStep `json:"steps"`
}

type logRecord struct {
	LatestVersion uint64     `json:"latest_version"`
	Logs          []TraceLog `json:"logs,omitempty"`
}

type ActorPrivileges struct {
	Group    string `json:"group"`
	Owner    bool   `json:"owner"`
	Executor bool   `json:"executor"`
	Updater  bool   `json:"updater"`
	Viewer   bool   `json:"viewer"`
}

type AccessPrivateData struct {
	Version      int    `json:"version"`
	ID           string `json:"id"`
	EncodeMethod string `json:"encode_method"`
	PrivateKey   string `json:"private_key"`
}

// PrivateAccessPayload
// data define to access file
type PrivateAccessPayload struct {
	PrivateData AccessPrivateData `json:"private_data"`
}

type ChainConnector struct {
	accessID                     string
	privateKey                   []byte
	innerClient                  *http.Client
	apiBase                      string
	domain                       string
	nonce                        string
	sessionID                    string
	timeout                      int
	localIP                      string
	headerNameSession            string
	headerNameTimestamp          string
	headerNameSignature          string
	headerNameSignatureAlgorithm string
	traceEnabled                 bool
}

const (
	TimeFormatLayout          = time.RFC3339
	SignatureMethodEd25519    = "ed25519"
	HeaderContentType         = "Content-Type"
	contentTypeJSON           = "application/json"
	pathErrorCode             = "error_code"
	pathErrorMessage          = "message"
	KeyEncodeMethodEd25519Hex = "ed25519-hex"
	DefaultKeyEncodeMethod    = KeyEncodeMethodEd25519Hex
)

func NewConnectorFromFile(privateFilepath string) (connector *ChainConnector, err error) {
	if _, err = os.Stat(privateFilepath); os.IsNotExist(err) {
		err = fmt.Errorf("can't find file '%s'", privateFilepath)
		return
	}
	var accessData AccessPrivateData
	if err = readJSON(privateFilepath, &accessData); err != nil {
		err = fmt.Errorf("read private data fail: %s", err.Error())
		return
	}
	return NewConnectorFromAccess(accessData)
}

func NewConnectorFromAccess(accessData AccessPrivateData) (connector *ChainConnector, err error) {
	var safePrivateKey []byte
	switch accessData.EncodeMethod {
	case KeyEncodeMethodEd25519Hex:
		var privateKey []byte
		if privateKey, err = hex.DecodeString(accessData.PrivateKey); err != nil {
			err = fmt.Errorf("decode private key fail: %s", err.Error())
			return
		}
		if ed25519.SeedSize == len(privateKey) {
			safePrivateKey = ed25519.NewKeyFromSeed(privateKey)
		} else {
			safePrivateKey = privateKey
		}

	default:
		err = fmt.Errorf("unsupport encode method: %s", accessData.EncodeMethod)
		return
	}
	return NewConnector(accessData.ID, safePrivateKey)
}

func NewConnector(accessID string, privateKey []byte) (connector *ChainConnector, err error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = DefaultMaxConnections
	t.MaxConnsPerHost = DefaultMaxConnections
	t.MaxIdleConnsPerHost = DefaultMaxConnections

	innerClient := &http.Client{
		Timeout:   DefaultClientTimeoutInSeconds * time.Second,
		Transport: t,
	}
	connector = &ChainConnector{
		accessID:     accessID,
		privateKey:   privateKey,
		innerClient:  innerClient,
		apiBase:      "",
		traceEnabled: false,
	}
	connector.SetProject(defaultProjectName)
	return
}

func (connector *ChainConnector) GetVersion() string {
	return SDKVersion
}

func (connector *ChainConnector) SetTrace(enabled bool) {
	connector.traceEnabled = enabled
}

func (connector *ChainConnector) SetProject(projectName string) {
	connector.headerNameSession = fmt.Sprintf("%s-Session", projectName)
	connector.headerNameTimestamp = fmt.Sprintf("%s-Timestamp", projectName)
	connector.headerNameSignature = fmt.Sprintf("%s-Signature", projectName)
	connector.headerNameSignatureAlgorithm = fmt.Sprintf("%s-SignatureAlgorithm", projectName)
}

func (connector *ChainConnector) Connect(host string, port int) (timeout int, err error) {
	return connector.ConnectToDomain(host, port, DefaultDomainName)
}

func (connector *ChainConnector) ConnectToDomain(host string, port int, domainName string) (timeout int, err error) {
	if "" == host {
		host = DefaultDomainHost
	}
	if port <= 0 || port > 0xFFFF {
		err = fmt.Errorf("invalid port %d", port)
		return
	}
	connector.apiBase = fmt.Sprintf("http://%s:%d/api/v%d", host, port, ApiVersion)
	connector.domain = domainName
	if connector.nonce, err = connector.newNonce(); err != nil {
		return
	}
	type signatureContent struct {
		Access             string `json:"access"`
		Timestamp          string `json:"timestamp"`
		Nonce              string `json:"nonce"`
		SignatureAlgorithm string `json:"signature_algorithm"`
	}
	var timestamp = time.Now().Format(TimeFormatLayout)
	var signatureAlgorithm = SignatureMethodEd25519
	var input = signatureContent{
		Access:             connector.accessID,
		Timestamp:          timestamp,
		Nonce:              connector.nonce,
		SignatureAlgorithm: signatureAlgorithm,
	}
	var signature string
	if signature, err = connector.base64Signature(input); err != nil {
		err = fmt.Errorf("signature fail: %s", err.Error())
		return
	}
	type requestPayload struct {
		ID    string `json:"id"`
		Nonce string `json:"nonce"`
	}
	var requestData = requestPayload{
		ID:    connector.accessID,
		Nonce: connector.nonce,
	}
	var header http.Header = map[string][]string{}
	header.Set(connector.headerNameTimestamp, timestamp)
	header.Set(connector.headerNameSignatureAlgorithm, signatureAlgorithm)
	header.Set(connector.headerNameSignature, signature)
	type responsePayload struct {
		Session string `json:"session"`
		Timeout int    `json:"timeout"`
		Address string `json:"address"`
	}
	var resp responsePayload
	if err = connector.rawRequest("POST", connector.toAPIPath("/sessions/"), header,
		&requestData, &resp); err != nil {
		return
	}
	connector.sessionID = resp.Session
	connector.timeout = resp.Timeout
	connector.localIP = resp.Address
	return
}

func (connector *ChainConnector) Activate() (err error) {
	var requestURL = connector.toAPIPath("/sessions/")
	err = connector.authenticatedRequest("PUT", requestURL, nil, nil)
	return
}

func (connector *ChainConnector) toAPIPath(path string) string {
	return fmt.Sprintf("%s%s", connector.apiBase, path)
}

func (connector *ChainConnector) toDomainPath(path string) string {
	return fmt.Sprintf("%s/domains/%s%s", connector.apiBase, connector.domain, path)
}

func (connector *ChainConnector) newNonce() (nonce string, err error) {
	const (
		originLength = 8
	)
	var buffer = make([]byte, originLength)
	if _, err = rand.Read(buffer); err != nil {
		err = fmt.Errorf("generate random nonce fail: %s", err.Error())
		return
	}
	nonce = hex.EncodeToString(buffer)
	return
}

func (connector *ChainConnector) base64Signature(data interface{}) (signature string, err error) {
	var payload []byte
	if payload, err = json.Marshal(data); err != nil {
		err = fmt.Errorf("generate content fail: %s", err.Error())
		return
	}
	var output = ed25519.Sign(connector.privateKey, payload)
	signature = base64.StdEncoding.EncodeToString(output)
	return
}

func (connector *ChainConnector) rawRequest(method, path string, header http.Header,
	requestBody interface{}, responsePayload interface{}) (err error) {
	var req *http.Request
	if nil == requestBody {
		req, err = http.NewRequest(method, path, nil)
	} else {
		var payload []byte
		if payload, err = json.MarshalIndent(requestBody, "", " "); err != nil {
			err = fmt.Errorf("marshal request body fail: %s", err.Error())
			return
		}
		req, err = http.NewRequest(method, path, bytes.NewBuffer(payload))
	}
	if err != nil {
		err = fmt.Errorf("build request fail: %s", err.Error())
		return
	}
	header.Set(HeaderContentType, contentTypeJSON)
	req.Header = header
	return connector.fetchRequestResult(req, responsePayload)
}

func (connector *ChainConnector) authenticatedRequest(method, path string, requestBody interface{},
	responsePayload interface{}) (err error) {
	if nil == requestBody {
		return connector.authenticatedRequestData(method, path, nil, responsePayload)
	} else {
		var bodyData []byte
		if bodyData, err = json.MarshalIndent(requestBody, "", ""); err != nil {
			err = fmt.Errorf("marshal request body fail: %s", err.Error())
			return
		}
		return connector.authenticatedRequestData(method, path, bodyData, responsePayload)
	}
}

func (connector *ChainConnector) authenticatedRequestData(method, path string, requestData []byte,
	responsePayload interface{}) (err error) {
	var req *http.Request
	req, err = connector.signatureRequest(method, path, requestData)
	return connector.fetchRequestResult(req, responsePayload)
}

func (connector *ChainConnector) authenticatedCheck(method, path string) (ok bool, err error) {
	var req *http.Request
	req, err = connector.signatureRequest(method, path, nil)
	return connector.checkRequestResult(req)
}

func (connector *ChainConnector) signatureRequest(method, path string, requestData []byte) (req *http.Request, err error) {
	const signatureAlgorithm = SignatureMethodEd25519
	var url *url.URL
	if url, err = url.Parse(path); err != nil {
		err = fmt.Errorf("parse url fail: %s", err.Error())
		return
	}
	var sessionID = connector.sessionID
	var timestamp = time.Now().Format(TimeFormatLayout)
	type signaturePayload struct {
		ID                 string `json:"id"`
		Method             string `json:"method"`
		URL                string `json:"url"`
		Body               string `json:"body"`
		Access             string `json:"access"`
		Timestamp          string `json:"timestamp"`
		Nonce              string `json:"nonce"`
		SignatureAlgorithm string `json:"signature_algorithm"`
	}
	var signatureContent = signaturePayload{
		ID:                 sessionID,
		Method:             method,
		URL:                url.Path,
		Access:             connector.accessID,
		Timestamp:          timestamp,
		Nonce:              connector.nonce,
		SignatureAlgorithm: signatureAlgorithm,
	}
	if nil == requestData {
		req, err = http.NewRequest(method, path, nil)
	} else {
		req, err = http.NewRequest(method, path, bytes.NewBuffer(requestData))
		req.Header.Set(HeaderContentType, contentTypeJSON)
	}
	if http.MethodPost == method || http.MethodPut == method ||
		http.MethodDelete == method || http.MethodPatch == method {
		//base64(sha256(body))
		if connector.traceEnabled {
			log.Printf("connector debug: request body(%d bytes):\n%s", len(requestData), requestData)
		}
		var bodyHash = sha256.Sum256(requestData)
		signatureContent.Body = base64.StdEncoding.EncodeToString(bodyHash[:])
	}
	var signature string
	if signature, err = connector.base64Signature(signatureContent); err != nil {
		err = fmt.Errorf("sign payload fail: %s", err.Error())
		return
	}
	req.Header.Set(connector.headerNameSession, sessionID)
	req.Header.Set(connector.headerNameTimestamp, timestamp)
	req.Header.Set(connector.headerNameSignatureAlgorithm, signatureAlgorithm)
	req.Header.Set(connector.headerNameSignature, signature)
	return
}

func (connector *ChainConnector) fetchRequestResult(req *http.Request, responsePayload interface{}) (err error) {
	var resp *http.Response
	if resp, err = connector.innerClient.Do(req); err != nil {
		err = fmt.Errorf("do request fail: %s", err.Error())
		return
	}
	if http.StatusOK != resp.StatusCode {
		err = fmt.Errorf("response with status code %d when request to '%s %s'",
			resp.StatusCode, req.Method, req.URL.Path)
		return
	}
	defer resp.Body.Close()
	var respData []byte
	if respData, err = ioutil.ReadAll(resp.Body); err != nil {
		err = fmt.Errorf("read result fail: %s", err.Error())
		return
	}
	if 0 != json.Get(respData, pathErrorCode).ToInt() {
		err = errors.New(json.Get(respData, "message").ToString())
	} else if nil != responsePayload {
		var data = json.Get(respData, "data")
		data.ToVal(responsePayload)
		err = data.LastError()
	}
	return
}

func (connector *ChainConnector) checkRequestResult(req *http.Request) (ok bool, err error) {
	var resp *http.Response
	if resp, err = connector.innerClient.Do(req); err != nil {
		err = fmt.Errorf("do request fail: %s", err.Error())
		return
	}
	if http.StatusOK != resp.StatusCode {
		ok = false
	} else {
		ok = true
	}
	return
}

func (connector *ChainConnector) GetStatus() (world, height uint64, previousBlock, genesisBlock, allocatedID string, err error) {
	type Payload struct {
		WorldVersion           uint64 `json:"world_version"`
		BlockHeight            uint64 `json:"block_height"`
		PreviousBlock          string `json:"previous_block,omitempty"`
		GenesisBlock           string `json:"genesis_block,omitempty"`
		AllocatedTransactionID string `json:"allocated_transaction_id,omitempty"`
	}
	var url = connector.toDomainPath("/status")
	var data Payload
	if err = connector.authenticatedRequest("GET", url, nil, &data); err != nil {
		return
	}
	world, height, previousBlock, genesisBlock, allocatedID = data.WorldVersion, data.BlockHeight, data.PreviousBlock,
		data.GenesisBlock, data.AllocatedTransactionID
	return
}

func (connector *ChainConnector) QuerySchemas(queryStart, maxRecord int) (names []string, offset, limit, total int, err error) {
	var url = connector.toDomainPath("/schemas/")
	type queryCondition struct {
		Offset int `json:"offset,omitempty"`
		Limit  int `json:"limit,omitempty"`
	}
	var condition = queryCondition{
		Offset: queryStart,
		Limit:  maxRecord,
	}
	type schemaSet struct {
		Schemas []string `json:"schemas,omitempty"`
		Limit   int      `json:"limit,omitempty"`
		Offset  int      `json:"offset,omitempty"`
		Total   int      `json:"total,omitempty"`
	}
	var data schemaSet
	if err = connector.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Schemas, data.Offset, data.Limit, data.Total, nil
}

func (connector *ChainConnector) RebuildIndex(schemaName string) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/index/", schemaName))
	err = connector.authenticatedRequest("POST", url, nil, nil)
	return
}

func (connector *ChainConnector) CreateSchema(schemaName string, properties []DocumentProperty) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	err = connector.authenticatedRequest("POST", url, properties, nil)
	return
}

func (connector *ChainConnector) UpdateSchema(schemaName string, properties []DocumentProperty) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	err = connector.authenticatedRequest("PUT", url, properties, nil)
	return
}

func (connector *ChainConnector) DeleteSchema(schemaName string) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	err = connector.authenticatedRequest("DELETE", url, nil, nil)
	return
}

func (connector *ChainConnector) HasSchema(schemaName string) (exists bool, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	exists, err = connector.authenticatedCheck("HEAD", url)
	return
}

func (connector *ChainConnector) GetSchema(schemaName string) (schema DocumentSchema, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	err = connector.authenticatedRequest("GET", url, nil, &schema)
	return
}

func (connector *ChainConnector) QueryContracts(queryStart, maxRecord int) (contracts []ContractInfo, offset, limit, total int,
	err error) {
	type queryResult struct {
		Contracts []ContractInfo `json:"contracts"`
		Offset    int            `json:"offset"`
		Limit     int            `json:"limit"`
		Total     int            `json:"total"`
	}
	type queryCondition struct {
		Keyword string `json:"keyword,omitempty"`
		Offset  int    `json:"offset,omitempty"`
		Limit   int    `json:"limit,omitempty"`
	}
	var url = connector.toDomainPath("/contracts/")
	var condition = queryCondition{
		Offset: queryStart,
		Limit:  maxRecord,
	}
	var data queryResult
	if err = connector.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Contracts, data.Offset, data.Limit, data.Total, nil
}

func (connector *ChainConnector) HasContract(contractName string) (exists bool, err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s", contractName))
	exists, err = connector.authenticatedCheck("HEAD", url)
	return
}

func (connector *ChainConnector) GetContract(contractName string) (define ContractDefine, err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	type responsePayload struct {
		Name    string `json:"name,omitempty"`
		Content string `json:"content,omitempty"`
	}
	var payload responsePayload
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s", contractName))
	err = connector.authenticatedRequest("GET", url, nil, &payload)
	if err != nil {
		err = fmt.Errorf("get contract content fail: %s", err.Error())
		return
	}
	if err = json.UnmarshalFromString(payload.Content, &define); err != nil {
		err = fmt.Errorf("unmarshal contract define fail: %s", err.Error())
		return
	}
	return
}

func (connector *ChainConnector) GetContractInfo(contractName string) (info ContractInfo, err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s/info/", contractName))
	err = connector.authenticatedRequest("GET", url, nil, &info)
	return
}

func (connector *ChainConnector) DeployContract(contractName string, define ContractDefine) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s", contractName))
	type requestPayload struct {
		Content string `json:"content"`
	}
	var request requestPayload
	if request.Content, err = json.MarshalToString(define); err != nil {
		err = fmt.Errorf("marshal contract fail: %s", err.Error())
		return
	}
	err = connector.authenticatedRequest("PUT", url, request, nil)
	return
}

func (connector *ChainConnector) CallContract(contractName string, parameters []string) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s/sessions/", contractName))
	type updatePayload struct {
		Parameters []string `json:"parameters,omitempty"`
	}
	var request = updatePayload{
		Parameters: parameters,
	}
	err = connector.authenticatedRequest("POST", url, request, nil)
	return
}

func (connector *ChainConnector) WithdrawContract(contractName string) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s", contractName))
	err = connector.authenticatedRequest("DELETE", url, nil, nil)
	return
}

func (connector *ChainConnector) EnableContractTrace(contractName string) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s/trace/", contractName))
	type requestPayload struct {
		Enable bool `json:"enable"`
	}
	var request = requestPayload{
		Enable: true,
	}
	err = connector.authenticatedRequest("PUT", url, request, nil)
	return
}

func (connector *ChainConnector) DisableContractTrace(contractName string) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s/trace/", contractName))
	type requestPayload struct {
		Enable bool `json:"enable"`
	}
	var request = requestPayload{
		Enable: false,
	}
	err = connector.authenticatedRequest("PUT", url, request, nil)
	return
}

func (connector *ChainConnector) QueryBlocks(beginHeight, endHeight uint64) (idList []string, currentHeight uint64, err error) {
	if endHeight <= beginHeight {
		err = fmt.Errorf("end height %d must greater than begin height %d", endHeight, beginHeight)
		return
	}
	type resultSet struct {
		Blocks []string `json:"blocks"`
		From   uint64   `json:"from"`
		To     uint64   `json:"to"`
		Height uint64   `json:"height"`
	}
	type queryCondition struct {
		From uint64 `json:"from"`
		To   uint64 `json:"to"`
	}
	var url = connector.toDomainPath("/blocks/")
	var condition = queryCondition{
		From: beginHeight,
		To:   endHeight,
	}
	var data resultSet
	if err = connector.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Blocks, data.Height, nil
}

func (connector *ChainConnector) GetBlock(blockID string) (block BlockData, err error) {
	if "" == blockID {
		err = errors.New("block ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/blocks/%s", blockID))
	err = connector.authenticatedRequest("GET", url, nil, &block)
	return
}

func (connector *ChainConnector) QueryTransactions(blockID string, start, maxRecord int) (idList []string,
	offset, limit, total int, err error) {
	if "" == blockID {
		err = errors.New("block ID required")
		return
	}
	type resultSet struct {
		Transactions []string `json:"transactions,omitempty"`
		Offset       int      `json:"offset"`
		Limit        int      `json:"limit"`
		Total        int      `json:"total"`
		HasMore      bool     `json:"has_more"`
	}
	type queryCondition struct {
		Offset uint64 `json:"offset,omitempty"`
		Limit  int    `json:"limit,omitempty"`
	}
	var url = connector.toDomainPath(fmt.Sprintf("/blocks/%s/transactions/", blockID))
	var condition = queryCondition{
		Offset: uint64(start),
		Limit:  maxRecord,
	}
	var data resultSet
	if err = connector.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Transactions, data.Offset, data.Limit, data.Total, nil
}

func (connector *ChainConnector) GetTransaction(blockID, transID string) (transaction TransactionData, err error) {
	if "" == blockID {
		err = errors.New("block ID required")
		return
	}
	if "" == transID {
		err = errors.New("transaction ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/blocks/%s/transactions/%s", blockID, transID))
	err = connector.authenticatedRequest("GET", url, nil, &transaction)
	return
}

func (connector *ChainConnector) GetSchemaLog(schemaName string) (version uint64, logs []TraceLog, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/logs/", schemaName))
	var data logRecord
	if err = connector.authenticatedRequest("GET", url, nil, &data); err != nil {
		return
	}
	version, logs = data.LatestVersion, data.Logs
	return
}

func (connector *ChainConnector) AddDocument(schemaName, docID, docContent string) (id string, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	type responsePayload struct {
		ID string `json:"id"`
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/", schemaName))
	var doc = Document{
		ID:      docID,
		Content: docContent,
	}
	var data responsePayload
	if err = connector.authenticatedRequest("POST", url, doc, &data); err != nil {
		return
	}
	return data.ID, nil
}

func (connector *ChainConnector) UpdateDocument(schemaName, docID, docContent string) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s", schemaName, docID))
	type requestPayload struct {
		Content string `json:"content,omitempty"`
	}
	var request = requestPayload{
		Content: docContent,
	}
	err = connector.authenticatedRequest("PUT", url, request, nil)
	return
}

func (connector *ChainConnector) UpdateDocumentProperty(schemaName, docID, propertyName, valueType string,
	value interface{}) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	if "" == propertyName {
		err = errors.New("property name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s/properties/%s", schemaName, docID, propertyName))
	var payload []byte
	switch valueType {
	case PropertyTypeInteger:
		type intPayload struct {
			Type  string `json:"type"`
			Value int    `json:"value"`
		}
		v, ok := value.(int)
		if !ok {
			err = errors.New("invalid integer value")
			return
		}
		var p = intPayload{
			Type:  valueType,
			Value: v,
		}
		if payload, err = json.MarshalIndent(p, "", ""); err != nil {
			err = fmt.Errorf("marshal payload fail: %s", err.Error())
			return
		}
	case PropertyTypeString:
		type stringPayload struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		v, ok := value.(string)
		if !ok {
			err = errors.New("invalid string value")
			return
		}
		var p = stringPayload{
			Type:  valueType,
			Value: v,
		}
		if payload, err = json.MarshalIndent(p, "", ""); err != nil {
			err = fmt.Errorf("marshal payload fail: %s", err.Error())
			return
		}
	case PropertyTypeBoolean:
		type boolPayload struct {
			Type  string `json:"type"`
			Value bool   `json:"value"`
		}
		v, ok := value.(bool)
		if !ok {
			err = errors.New("invalid bool value")
			return
		}
		var p = boolPayload{
			Type:  valueType,
			Value: v,
		}
		if payload, err = json.MarshalIndent(p, "", ""); err != nil {
			err = fmt.Errorf("marshal payload fail: %s", err.Error())
			return
		}
	case PropertyTypeCurrency:
		fallthrough
	case PropertyTypeFloat:
		type floatPayload struct {
			Type  string  `json:"type"`
			Value float64 `json:"value"`
		}
		v, ok := value.(float64)
		if !ok {
			err = errors.New("invalid float value")
			return
		}
		var p = floatPayload{
			Type:  valueType,
			Value: v,
		}
		if payload, err = json.MarshalIndent(p, "", ""); err != nil {
			err = fmt.Errorf("marshal payload fail: %s", err.Error())
			return
		}
	default:
		err = fmt.Errorf("unsupported value type %s", valueType)
		return
	}
	err = connector.authenticatedRequestData("PUT", url, payload, nil)
	return
}

func (connector *ChainConnector) RemoveDocument(schemaName, docID string) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s", schemaName, docID))
	err = connector.authenticatedRequest("DELETE", url, nil, nil)
	return
}

func (connector *ChainConnector) HasDocument(schemaName, docID string) (exists bool, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s", schemaName, docID))
	exists, err = connector.authenticatedCheck("HEAD", url)
	return
}

func (connector *ChainConnector) GetDocument(schemaName, docID string) (content string, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s", schemaName, docID))
	var data Document
	if err = connector.authenticatedRequest("GET", url, nil, &data); err != nil {
		return
	}
	return data.Content, nil
}

func (connector *ChainConnector) GetDocumentLog(schemaName, docID string) (version uint64, logs []TraceLog, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s/logs/", schemaName, docID))
	var data logRecord
	if err = connector.authenticatedRequest("GET", url, nil, &data); err != nil {
		return
	}
	return data.LatestVersion, data.Logs, nil
}

func (connector *ChainConnector) QueryDocuments(schemaName string, condition QueryCondition) (
	documents []Document, limit, offset, total int, err error) {
	type documentSet struct {
		Documents []Document `json:"documents,omitempty"`
		Limit     int        `json:"limit,omitempty"`
		Offset    int        `json:"offset,omitempty"`
		Total     int        `json:"total,omitempty"`
	}
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/queries/schemas/%s/docs/", schemaName))
	var data documentSet
	if err = connector.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Documents, data.Limit, data.Offset, data.Total, nil
}

func (connector *ChainConnector) GetDocumentActors(schemaName, docID string) (actors []ActorPrivileges, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s/actors/", schemaName, docID))
	actors = make([]ActorPrivileges, 0)
	err = connector.authenticatedRequest("GET", url, nil, &actors)
	return
}

func (connector *ChainConnector) UpdateDocumentActors(schemaName, docID string, actors []ActorPrivileges) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s/actors/", schemaName, docID))
	type requestPayload struct {
		Actors []ActorPrivileges `json:"actors"`
	}
	var request = requestPayload{Actors: actors}
	err = connector.authenticatedRequest("PUT", url, request, nil)
	return
}

func (connector *ChainConnector) GetSchemaActors(schemaName string) (actors []ActorPrivileges, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/actors/", schemaName))
	actors = make([]ActorPrivileges, 0)
	err = connector.authenticatedRequest("GET", url, nil, &actors)
	return
}

func (connector *ChainConnector) UpdateSchemaActors(schemaName string, actors []ActorPrivileges) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/schemas/%s/actors/", schemaName))
	type requestPayload struct {
		Actors []ActorPrivileges `json:"actors"`
	}
	var request = requestPayload{Actors: actors}
	err = connector.authenticatedRequest("PUT", url, request, nil)
	return
}

func (connector *ChainConnector) GetContractActors(contractName string) (actors []ActorPrivileges, err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s/actors/", contractName))
	actors = make([]ActorPrivileges, 0)
	err = connector.authenticatedRequest("GET", url, nil, &actors)
	return
}

func (connector *ChainConnector) UpdateContractActors(contractName string, actors []ActorPrivileges) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = connector.toDomainPath(fmt.Sprintf("/contracts/%s/actors/", contractName))
	type requestPayload struct {
		Actors []ActorPrivileges `json:"actors"`
	}
	var request = requestPayload{Actors: actors}
	err = connector.authenticatedRequest("PUT", url, request, nil)
	return
}

func readJSON(filename string, content interface{}) (err error) {
	if _, err = os.Stat(filename); os.IsNotExist(err) {
		err = fmt.Errorf("can't find file '%s'", filename)
		return
	}
	var file *os.File
	if file, err = os.Open(filename); err != nil {
		err = fmt.Errorf("open '%s' fail: %s", filename, err.Error())
		return
	}
	defer file.Close()
	var decoder = json.NewDecoder(file)
	if err = decoder.Decode(content); err != nil {
		err = fmt.Errorf("parse content of file '%s' fail: %s", filename, err.Error())
		return
	}
	return
}
