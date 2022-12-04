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
	ProjectName                   = "Taiyi"
	SDKVersion                    = "0.1.2"
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

type AccessPrivateData struct {
	Version      int    `json:"version"`
	ID           string `json:"id"`
	EncodeMethod string `json:"encode_method"`
	PrivateKey   string `json:"private_key"`
}

type ChainClient struct {
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

func NewClientFromFile(privateFilepath string) (client *ChainClient, err error) {
	if _, err = os.Stat(privateFilepath); os.IsNotExist(err) {
		err = fmt.Errorf("can't find file '%s'", privateFilepath)
		return
	}
	var accessData AccessPrivateData
	if err = readJSON(privateFilepath, &accessData); err != nil {
		err = fmt.Errorf("read private data fail: %s", err.Error())
		return
	}
	return NewClientFromAccess(accessData)
}

func NewClientFromAccess(accessData AccessPrivateData) (client *ChainClient, err error) {
	var privateKey []byte
	switch accessData.EncodeMethod {
	case DefaultKeyEncodeMethod:
		if privateKey, err = hex.DecodeString(accessData.PrivateKey); err != nil {
			err = fmt.Errorf("decode private key fail: %s", err.Error())
			return
		}
	default:
		err = fmt.Errorf("unsupport encode method: %s", accessData.EncodeMethod)
		return
	}
	return NewClient(accessData.ID, privateKey)
}

func NewClient(accessID string, privateKey []byte) (client *ChainClient, err error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = DefaultMaxConnections
	t.MaxConnsPerHost = DefaultMaxConnections
	t.MaxIdleConnsPerHost = DefaultMaxConnections

	innerClient := &http.Client{
		Timeout:   DefaultClientTimeoutInSeconds * time.Second,
		Transport: t,
	}
	client = &ChainClient{
		accessID:                     accessID,
		privateKey:                   privateKey,
		innerClient:                  innerClient,
		apiBase:                      "",
		headerNameSession:            fmt.Sprintf("%s-Session", ProjectName),
		headerNameTimestamp:          fmt.Sprintf("%s-Timestamp", ProjectName),
		headerNameSignature:          fmt.Sprintf("%s-Signature", ProjectName),
		headerNameSignatureAlgorithm: fmt.Sprintf("%s-SignatureAlgorithm", ProjectName),
	}
	return
}

func (client *ChainClient) GetVersion() string {
	return SDKVersion
}

func (client *ChainClient) Connect(host string, port int) (timeout int, err error) {
	return client.ConnectToDomain(host, port, DefaultDomainName)
}

func (client *ChainClient) ConnectToDomain(host string, port int, domainName string) (timeout int, err error) {
	if "" == host {
		host = DefaultDomainHost
	}
	if port <= 0 || port > 0xFFFF {
		err = fmt.Errorf("invalid port %d", port)
		return
	}
	client.apiBase = fmt.Sprintf("http://%s:%d/api/v%d", host, port, ApiVersion)
	client.domain = domainName
	if client.nonce, err = client.newNonce(); err != nil {
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
		Access:             client.accessID,
		Timestamp:          timestamp,
		Nonce:              client.nonce,
		SignatureAlgorithm: signatureAlgorithm,
	}
	var signature string
	if signature, err = client.base64Signature(input); err != nil {
		err = fmt.Errorf("signature fail: %s", err.Error())
		return
	}
	type requestPayload struct {
		ID    string `json:"id"`
		Nonce string `json:"nonce"`
	}
	var requestData = requestPayload{
		ID:    client.accessID,
		Nonce: client.nonce,
	}
	var header http.Header = map[string][]string{}
	header.Set(client.headerNameTimestamp, timestamp)
	header.Set(client.headerNameSignatureAlgorithm, signatureAlgorithm)
	header.Set(client.headerNameSignature, signature)
	type responsePayload struct {
		Session string `json:"session"`
		Timeout int    `json:"timeout"`
		Address string `json:"address"`
	}
	var resp responsePayload
	if err = client.rawRequest("POST", client.toAPIPath("/sessions/"), header,
		&requestData, &resp); err != nil {
		return
	}
	client.sessionID = resp.Session
	client.timeout = resp.Timeout
	client.localIP = resp.Address
	return
}

func (client *ChainClient) Activate() (err error) {
	var requestURL = client.toAPIPath("/sessions/")
	err = client.authenticatedRequest("PUT", requestURL, nil, nil)
	return
}

func (client *ChainClient) toAPIPath(path string) string {
	return fmt.Sprintf("%s%s", client.apiBase, path)
}

func (client *ChainClient) toDomainPath(path string) string {
	return fmt.Sprintf("%s/domains/%s%s", client.apiBase, client.domain, path)
}

func (client *ChainClient) newNonce() (nonce string, err error) {
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

func (client *ChainClient) base64Signature(data interface{}) (signature string, err error) {
	var payload []byte
	if payload, err = json.Marshal(data); err != nil {
		err = fmt.Errorf("generate content fail: %s", err.Error())
		return
	}
	var output = ed25519.Sign(client.privateKey, payload)
	signature = base64.StdEncoding.EncodeToString(output)
	return
}

func (client *ChainClient) rawRequest(method, path string, header http.Header,
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
	return client.fetchRequestResult(req, responsePayload)
}

func (client *ChainClient) authenticatedRequest(method, path string, requestBody interface{},
	responsePayload interface{}) (err error) {
	if nil == requestBody {
		return client.authenticatedRequestData(method, path, nil, responsePayload)
	} else {
		var bodyData []byte
		if bodyData, err = json.MarshalIndent(requestBody, "", ""); err != nil {
			err = fmt.Errorf("marshal request body fail: %s", err.Error())
			return
		}
		return client.authenticatedRequestData(method, path, bodyData, responsePayload)
	}
}

func (client *ChainClient) authenticatedRequestData(method, path string, requestData []byte,
	responsePayload interface{}) (err error) {
	var req *http.Request
	req, err = client.signatureRequest(method, path, requestData)
	return client.fetchRequestResult(req, responsePayload)
}

func (client *ChainClient) authenticatedCheck(method, path string) (ok bool, err error) {
	var req *http.Request
	req, err = client.signatureRequest(method, path, nil)
	return client.checkRequestResult(req)
}

func (client *ChainClient) signatureRequest(method, path string, requestData []byte) (req *http.Request, err error) {
	const signatureAlgorithm = SignatureMethodEd25519
	var url *url.URL
	if url, err = url.Parse(path); err != nil {
		err = fmt.Errorf("parse url fail: %s", err.Error())
		return
	}
	var sessionID = client.sessionID
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
		Access:             client.accessID,
		Timestamp:          timestamp,
		Nonce:              client.nonce,
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
		//log.Printf("client debug: request body(%d bytes):\n%s", len(requestData), requestData)
		var bodyHash = sha256.Sum256(requestData)
		signatureContent.Body = base64.StdEncoding.EncodeToString(bodyHash[:])
	}
	var signature string
	if signature, err = client.base64Signature(signatureContent); err != nil {
		err = fmt.Errorf("sign payload fail: %s", err.Error())
		return
	}
	req.Header.Set(client.headerNameSession, sessionID)
	req.Header.Set(client.headerNameTimestamp, timestamp)
	req.Header.Set(client.headerNameSignatureAlgorithm, signatureAlgorithm)
	req.Header.Set(client.headerNameSignature, signature)
	return
}

func (client *ChainClient) fetchRequestResult(req *http.Request, responsePayload interface{}) (err error) {
	var resp *http.Response
	if resp, err = client.innerClient.Do(req); err != nil {
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

func (client *ChainClient) checkRequestResult(req *http.Request) (ok bool, err error) {
	var resp *http.Response
	if resp, err = client.innerClient.Do(req); err != nil {
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

func (client *ChainClient) GetStatus() (world, height uint64, previousBlock, genesisBlock, allocatedID string, err error) {
	type Payload struct {
		WorldVersion           uint64 `json:"world_version"`
		BlockHeight            uint64 `json:"block_height"`
		PreviousBlock          string `json:"previous_block,omitempty"`
		GenesisBlock           string `json:"genesis_block,omitempty"`
		AllocatedTransactionID string `json:"allocated_transaction_id,omitempty"`
	}
	var url = client.toDomainPath("/status")
	var data Payload
	if err = client.authenticatedRequest("GET", url, nil, &data); err != nil {
		return
	}
	world, height, previousBlock, genesisBlock, allocatedID = data.WorldVersion, data.BlockHeight, data.PreviousBlock,
		data.GenesisBlock, data.AllocatedTransactionID
	return
}

func (client *ChainClient) QuerySchemas(queryStart, maxRecord int) (names []string, offset, limit, total int, err error) {
	var url = client.toDomainPath("/schemas/")
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
	if err = client.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Schemas, data.Offset, data.Limit, data.Total, nil
}

func (client *ChainClient) RebuildIndex(schemaName string) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/index/", schemaName))
	err = client.authenticatedRequest("POST", url, nil, nil)
	return
}

func (client *ChainClient) CreateSchema(schemaName string, properties []DocumentProperty) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	err = client.authenticatedRequest("POST", url, properties, nil)
	return
}

func (client *ChainClient) UpdateSchema(schemaName string, properties []DocumentProperty) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	err = client.authenticatedRequest("PUT", url, properties, nil)
	return
}

func (client *ChainClient) DeleteSchema(schemaName string) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	err = client.authenticatedRequest("DELETE", url, nil, nil)
	return
}

func (client *ChainClient) HasSchema(schemaName string) (exists bool, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	exists, err = client.authenticatedCheck("HEAD", url)
	return
}

func (client *ChainClient) GetSchema(schemaName string) (schema DocumentSchema, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s", schemaName))
	err = client.authenticatedRequest("GET", url, nil, &schema)
	return
}

func (client *ChainClient) QueryContracts(queryStart, maxRecord int) (contracts []ContractInfo, offset, limit, total int,
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
	var url = client.toDomainPath("/contracts/")
	var condition = queryCondition{
		Offset: queryStart,
		Limit:  maxRecord,
	}
	var data queryResult
	if err = client.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Contracts, data.Offset, data.Limit, data.Total, nil
}

func (client *ChainClient) DeployContract(contractName string, define ContractDefine) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/contracts/%s", contractName))
	type requestPayload struct {
		Content string `json:"content"`
	}
	var request requestPayload
	if request.Content, err = json.MarshalToString(define); err != nil {
		err = fmt.Errorf("marshal contract fail: %s", err.Error())
		return
	}
	err = client.authenticatedRequest("PUT", url, request, nil)
	return
}

func (client *ChainClient) CallContract(contractName string, parameters []string) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/contracts/%s/sessions/", contractName))
	type updatePayload struct {
		Parameters []string `json:"parameters,omitempty"`
	}
	var request = updatePayload{
		Parameters: parameters,
	}
	err = client.authenticatedRequest("POST", url, request, nil)
	return
}

func (client *ChainClient) WithdrawContract(contractName string) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/contracts/%s", contractName))
	err = client.authenticatedRequest("DELETE", url, nil, nil)
	return
}

func (client *ChainClient) EnableContractTrace(contractName string) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/contracts/%s/trace/", contractName))
	type requestPayload struct {
		Enable bool `json:"enable"`
	}
	var request = requestPayload{
		Enable: true,
	}
	err = client.authenticatedRequest("PUT", url, request, nil)
	return
}

func (client *ChainClient) DisableContractTrace(contractName string) (err error) {
	if "" == contractName {
		err = errors.New("contract name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/contracts/%s/trace/", contractName))
	type requestPayload struct {
		Enable bool `json:"enable"`
	}
	var request = requestPayload{
		Enable: false,
	}
	err = client.authenticatedRequest("PUT", url, request, nil)
	return
}

func (client *ChainClient) QueryBlocks(beginHeight, endHeight uint64) (idList []string, currentHeight uint64, err error) {
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
	var url = client.toDomainPath("/blocks/")
	var condition = queryCondition{
		From: beginHeight,
		To:   endHeight,
	}
	var data resultSet
	if err = client.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Blocks, data.Height, nil
}

func (client *ChainClient) GetBlock(blockID string) (block BlockData, err error) {
	if "" == blockID {
		err = errors.New("block ID required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/blocks/%s", blockID))
	err = client.authenticatedRequest("GET", url, nil, &block)
	return
}

func (client *ChainClient) QueryTransactions(blockID string, start, maxRecord int) (idList []string,
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
	var url = client.toDomainPath(fmt.Sprintf("/blocks/%s/transactions/", blockID))
	var condition = queryCondition{
		Offset: uint64(start),
		Limit:  maxRecord,
	}
	var data resultSet
	if err = client.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Transactions, data.Offset, data.Limit, data.Total, nil
}

func (client *ChainClient) GetTransaction(blockID, transID string) (transaction TransactionData, err error) {
	if "" == blockID {
		err = errors.New("block ID required")
		return
	}
	if "" == transID {
		err = errors.New("transaction ID required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/blocks/%s/transactions/%s", blockID, transID))
	err = client.authenticatedRequest("GET", url, nil, &transaction)
	return
}

func (client *ChainClient) GetSchemaLog(schemaName string) (version uint64, logs []TraceLog, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/logs/", schemaName))
	var data logRecord
	if err = client.authenticatedRequest("GET", url, nil, &data); err != nil {
		return
	}
	version, logs = data.LatestVersion, data.Logs
	return
}

func (client *ChainClient) AddDocument(schemaName, docID, docContent string) (id string, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	type responsePayload struct {
		ID string `json:"id"`
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/docs/", schemaName))
	var doc = Document{
		ID:      docID,
		Content: docContent,
	}
	var data responsePayload
	if err = client.authenticatedRequest("POST", url, doc, &data); err != nil {
		return
	}
	return data.ID, nil
}

func (client *ChainClient) UpdateDocument(schemaName, docID, docContent string) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s", schemaName, docID))
	type requestPayload struct {
		Content string `json:"content,omitempty"`
	}
	var request = requestPayload{
		Content: docContent,
	}
	err = client.authenticatedRequest("PUT", url, request, nil)
	return
}

func (client *ChainClient) UpdateDocumentProperty(schemaName, docID, propertyName, valueType string,
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
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s/properties/%s", schemaName, docID, propertyName))
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
	err = client.authenticatedRequestData("PUT", url, payload, nil)
	return
}

func (client *ChainClient) RemoveDocument(schemaName, docID string) (err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s", schemaName, docID))
	err = client.authenticatedRequest("DELETE", url, nil, nil)
	return
}

func (client *ChainClient) HasDocument(schemaName, docID string) (exists bool, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s", schemaName, docID))
	exists, err = client.authenticatedCheck("HEAD", url)
	return
}

func (client *ChainClient) GetDocument(schemaName, docID string) (content string, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s", schemaName, docID))
	var data Document
	if err = client.authenticatedRequest("GET", url, nil, &data); err != nil {
		return
	}
	return data.Content, nil
}

func (client *ChainClient) GetDocumentLog(schemaName, docID string) (version uint64, logs []TraceLog, err error) {
	if "" == schemaName {
		err = errors.New("schema name required")
		return
	}
	if "" == docID {
		err = errors.New("document ID required")
		return
	}
	var url = client.toDomainPath(fmt.Sprintf("/schemas/%s/docs/%s/logs/", schemaName, docID))
	var data logRecord
	if err = client.authenticatedRequest("GET", url, nil, &data); err != nil {
		return
	}
	return data.LatestVersion, data.Logs, nil
}

func (client *ChainClient) QueryDocuments(schemaName string, condition QueryCondition) (
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
	var url = client.toDomainPath(fmt.Sprintf("/queries/schemas/%s/docs/", schemaName))
	var data documentSet
	if err = client.authenticatedRequest("POST", url, condition, &data); err != nil {
		return
	}
	return data.Documents, data.Limit, data.Offset, data.Total, nil
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
