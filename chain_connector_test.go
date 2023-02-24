package client

import (
	"fmt"
	json "github.com/json-iterator/go"
	"github.com/tidwall/sjson"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	configFilename = "test.json"
	keyFilename    = "access_key.json"
)

// testHost       = "192.168.3.110"
// DefaultAPIPort = 9100
// Sample
//
//	{
//		"host": "",
//		"port": 9100
//	}
type testConfig struct {
	Project string `json:"project,omitempty"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Debug   bool   `json:"debug,omitempty"`
}

// Sample Access Key
//{
//	"private_data": {
//		"version": 1,
//		"id": "cc5k2gvpgon8pg03tqqg",
//		"encode_method": "ed25519-hex",
//		"private_key": "d58253e37c54956c3e2f48b4f711c7ade10b82842381d50778bb551b426e00cfe66532b335dde99268114e2b31102b92f5a18efc71469c31ce9ab0e4afba99a1"
//	}
//}

func loadObject[T any](targetPath string) (obj T, err error) {
	if _, err = os.Stat(targetPath); os.IsNotExist(err) {
		err = fmt.Errorf("can't find file '%s'", targetPath)
		return
	}
	var targetFile *os.File
	if targetFile, err = os.Open(targetPath); err != nil {
		err = fmt.Errorf("load file '%s' fail: %s", targetPath, err.Error())
		return
	}
	var decoder = json.NewDecoder(targetFile)
	if err = decoder.Decode(&obj); err != nil {
		err = fmt.Errorf("parse content of file '%s' fail: %s", targetPath, err.Error())
		return
	}
	return
}

func clearClientEnvironment() {
}

func prepareClientEnvironment() (c *ChainConnector, r *rand.Rand, err error) {
	log.SetFlags(log.Ldate | log.Lmicroseconds)
	clearClientEnvironment()
	r = rand.New(rand.NewSource(time.Now().UnixNano()))
	var config testConfig
	if config, err = loadObject[testConfig](configFilename); err != nil {
		err = fmt.Errorf("load test configure fail: %s", err.Error())
		return
	}

	var access PrivateAccessPayload
	if access, err = loadObject[PrivateAccessPayload](keyFilename); err != nil {
		err = fmt.Errorf("load access key fail: %s", err.Error())
		return
	}
	if c, err = NewConnectorFromAccess(access.PrivateData); err != nil {
		err = fmt.Errorf("create connector fail: %s", err.Error())
		return
	}
	if "" != config.Project {
		c.SetProject(config.Project)
	}
	if config.Debug {
		//enable trace
		c.SetTrace(true)
	}
	_, err = c.Connect(config.Host, config.Port)
	return
}

func combineCRUD(id int, c *ChainConnector, r *rand.Rand) (operates int, elapsed time.Duration, err error) {
	const (
		docCount    = 10
		propertyAge = "age"
	)
	operates = 0
	var beginTime = time.Now()
	var schemaName = fmt.Sprintf("combine_crud_%d_%d", id, r.Intn(99999999))
	var properties []DocumentProperty
	var exists bool
	if exists, err = c.HasSchema(schemaName); err != nil {
		err = fmt.Errorf("check schema fail: %s", err.Error())
		return
	} else if exists {
		if err = c.DeleteSchema(schemaName); err != nil {
			err = fmt.Errorf("delete previous schema %s fail: %s", schemaName, err.Error())
			return
		}
	}
	if err = c.CreateSchema(schemaName, properties); err != nil {
		err = fmt.Errorf("create schema fail: %s", err.Error())
		return
	}
	operates++
	defer func() {
		c.DeleteSchema(schemaName)
		operates++
		elapsed = time.Now().Sub(beginTime)
	}()
	var content = "{}"
	for i := 0; i < docCount; i++ {
		if _, err = c.AddDocument(schemaName, fmt.Sprintf("doc_%d", i), content); err != nil {
			return
		}
		operates++
	}
	defer func() {
		for i := 0; i < docCount; i++ {
			var docID = fmt.Sprintf("doc_%d", i)
			c.RemoveDocument(schemaName, docID)
			operates++
		}
	}()
	properties = []DocumentProperty{
		{
			Name: propertyAge,
			Type: PropertyTypeInteger,
		},
		{
			Name: "enabled",
			Type: PropertyTypeBoolean,
		},
	}
	if err = c.UpdateSchema(schemaName, properties); err != nil {
		return
	}
	operates++
	for i := 0; i < docCount; i++ {
		var docID = fmt.Sprintf("doc_%d", i)
		if 0 == i%2 {
			content = "{\"age\": 0, \"enabled\": false}"
		} else {
			content = "{\"age\": 0, \"enabled\": true}"
		}
		if err = c.UpdateDocument(schemaName, docID, content); err != nil {
			return
		}
		operates++
	}
	for i := 0; i < docCount; i++ {
		var docID = fmt.Sprintf("doc_%d", i)
		if err = c.UpdateDocumentProperty(schemaName, docID, propertyAge, PropertyTypeInteger, i); err != nil {
			return
		}
	}
	var queryRecords = func(c *ChainConnector, caseName string, schemaName string,
		condition QueryCondition, expectTotal int, expect []int) (err error) {
		var records []Document
		limit, offset, total := 0, 0, 0
		if records, limit, offset, total, err = c.QueryDocuments(schemaName, condition); err != nil {
			err = fmt.Errorf("%s fail: %s", caseName, err.Error())
			return
		}
		operates++
		var expectLimit = condition.Limit
		if 0 != expectLimit {
			if limit != expectLimit {
				err = fmt.Errorf("unexpected limit %d => %d when %s", limit, expectLimit, caseName)
				return
			}
		}
		var expectOffset = condition.Offset
		if 0 != expectOffset {
			if offset != expectOffset {
				err = fmt.Errorf("unexpected offset %d => %d when %s", offset, expectOffset, caseName)
				return
			}
		}

		if total != expectTotal {
			err = fmt.Errorf("unexpected total count %d => %d when %s", total, expectTotal, caseName)
			return
		}
		var resultCount = len(records)
		if resultCount != len(expect) {
			err = fmt.Errorf("%s: unexpected result count %d => %d", caseName, resultCount, len(expect))
			return
		}
		//log.Printf("%s result: %d / %d return from %d (max %d)",
		//	caseName, resultCount, total, offset, limit)
		for i, doc := range records {
			var value = json.Get([]byte(doc.Content), propertyAge).ToInt()
			if value != expect[i] {
				err = fmt.Errorf("%s: unexpected property of doc '%s': %d => %d",
					caseName, doc.ID, value, expect[i])
				return
			}
			//log.Printf("%s record-%d: %s: %s", caseName, i, doc.ID, doc.Content)
		}
		return
	}
	{
		//ascend query
		const (
			l = 5
			o = 3
		)
		var query = new(QueryCondition).AscendBy(propertyAge).MaxRecord(l).SetOffset(o)

		var expected = []int{3, 4, 5, 6, 7}
		if err = queryRecords(c, "ascend query", schemaName, *query,
			docCount, expected); err != nil {
			return
		}
	}
	{
		//descend query with filter
		const (
			l     = 3
			total = 4
		)
		var query = new(QueryCondition).
			DescendBy(propertyAge).
			MaxRecord(l).
			PropertyEqual("enabled", "true").
			PropertyLessThan(propertyAge, "8")

		var expected = []int{7, 5, 3}
		if err = queryRecords(c, "descend filter", schemaName, *query,
			total, expected); err != nil {
			return
		}
	}
	return
}

func contractOperates(id int, c *ChainConnector, r *rand.Rand, loopCount int, traceEnabled bool) (operates int, elapsed time.Duration, err error) {
	const (
		propertyCatalog   = "catalog"
		propertyBalance   = "balance"
		propertyNumber    = "number"
		propertyAvailable = "available"
		propertyWeight    = "weight"
	)
	operates = 0
	var beginTime = time.Now()
	var schemaName = fmt.Sprintf("contract_operates_%d_%d", id, r.Intn(99999999))
	var properties = []DocumentProperty{
		{
			Name:    propertyCatalog,
			Type:    PropertyTypeString,
			Indexed: true,
		},
		{
			Name:    propertyBalance,
			Type:    PropertyTypeCurrency,
			Indexed: true,
		},
		{
			Name:    propertyNumber,
			Type:    PropertyTypeInteger,
			Indexed: true,
		},
		{
			Name: propertyAvailable,
			Type: PropertyTypeBoolean,
		},
		{
			Name:    propertyWeight,
			Type:    PropertyTypeFloat,
			Indexed: true,
		},
	}
	var exists bool
	if exists, err = c.HasSchema(schemaName); err != nil {
		err = fmt.Errorf("check schema fail: %s", err.Error())
		return
	} else if exists {
		if err = c.DeleteSchema(schemaName); err != nil {
			err = fmt.Errorf("delete previous schema %s fail: %s", schemaName, err.Error())
			return
		}
	}
	if err = c.CreateSchema(schemaName, properties); err != nil {
		err = fmt.Errorf("create schema fail: %s", err.Error())
		return
	}
	operates++
	defer func() {
		c.DeleteSchema(schemaName)
		operates++
		elapsed = time.Now().Sub(beginTime)
	}()
	var varName = "$s"
	var createContract = ContractDefine{
		Steps: []ContractStep{
			{
				Action: "create_doc",
				Params: []string{varName, "@1", "@2"},
			},
			{
				Action: "set_property",
				Params: []string{varName, propertyCatalog, "@3"},
			},
			{
				Action: "set_property",
				Params: []string{varName, propertyBalance, "@4"},
			},
			{
				Action: "set_property",
				Params: []string{varName, propertyNumber, "@5"},
			},
			{
				Action: "set_property",
				Params: []string{varName, propertyAvailable, "@6"},
			},
			{
				Action: "set_property",
				Params: []string{varName, propertyWeight, "@7"},
			},
			{
				Action: "update_doc",
				Params: []string{"@1", varName},
			},
			{
				Action: "submit",
			},
		},
	}
	var deleteContract = ContractDefine{
		Steps: []ContractStep{
			{
				Action: "delete_doc",
				Params: []string{"@1", "@2"},
			},
			{
				Action: "submit",
			},
		},
	}
	for i := 0; i < loopCount; i++ {
		var createContractName = fmt.Sprintf("contract_create_%d_%d", id, i)
		exists, err = c.HasContract(createContractName)
		if exists {
			if err = c.WithdrawContract(createContractName); err != nil {
				err = fmt.Errorf("withdraw previous contract %s fail: %s", createContractName, err.Error())
				return
			}
		}

		if err = c.DeployContract(createContractName, createContract); err != nil {
			err = fmt.Errorf("deploy contract fail: %s", err.Error())
			return
		}
		operates++
		if _, err = c.GetContract(createContractName); err != nil {
			err = fmt.Errorf("get contract define fail: %s", err.Error())
			return
		}

		var deleteContractName = fmt.Sprintf("contract_delete_%d_%d", id, i)
		exists, err = c.HasContract(deleteContractName)
		if exists {
			if err = c.WithdrawContract(deleteContractName); err != nil {
				err = fmt.Errorf("withdraw previous contract %s fail: %s", deleteContractName, err.Error())
				return
			}
		}
		if err = c.DeployContract(deleteContractName, deleteContract); err != nil {
			err = fmt.Errorf("deploy contract fail: %s", err.Error())
			return
		}
		operates++
		var docID = fmt.Sprintf("test_%d_%d", id, i)
		var parameters = []string{
			schemaName,
			docID,
			schemaName,
			fmt.Sprintf("%f", r.Float64()),
			fmt.Sprintf("%d", r.Int()),
			fmt.Sprintf("%t", 1 == r.Intn(10)%2),
			fmt.Sprintf("%f", r.Float64()),
		}
		if traceEnabled {
			var info ContractInfo
			if info, err = c.GetContractInfo(createContractName); err != nil {
				err = fmt.Errorf("get contract info fail: %s", err.Error())
				return
			}
			if !info.Trace {
				if err = c.EnableContractTrace(createContractName); err != nil {
					err = fmt.Errorf("enable trace fail: %s", err.Error())
					return
				}
				operates++
			}
		}
		if err = c.CallContract(createContractName, parameters); err != nil {
			err = fmt.Errorf("call create contract fail: %s", err.Error())
			return
		}
		operates++
		if err = c.CallContract(deleteContractName, []string{schemaName, docID}); err != nil {
			err = fmt.Errorf("call delete contract fail: %s", err.Error())
			return
		}
		operates++
		if _, _, _, _, err = c.QueryContracts(0, 0); err != nil {
			err = fmt.Errorf("query contract before remove fail: %s", err.Error())
			return
		}
		operates++
		if traceEnabled {
			if err = c.DisableContractTrace(createContractName); err != nil {
				err = fmt.Errorf("disable trace fail: %s", err.Error())
				return
			}
			operates++
		}
		if err = c.WithdrawContract(createContractName); err != nil {
			err = fmt.Errorf("withdraw create contract fail: %s", err.Error())
			return
		}
		operates++
		if err = c.WithdrawContract(deleteContractName); err != nil {
			err = fmt.Errorf("withdraw delete contract fail: %s", err.Error())
			return
		}
		operates++
		if _, _, _, _, err = c.QueryContracts(0, 0); err != nil {
			err = fmt.Errorf("query contract afer remove fail: %s", err.Error())
			return
		}
		operates++
	}

	return
}

func walkAllBlocks(c *ChainConnector, currentHeight uint64, maxCount int, stepLength uint64) (operates, walked int, elapsed time.Duration, err error) {
	const (
		lowestHeight = 1
	)
	operates, walked = 0, 0
	var beginTime = time.Now()
	var endHeight = currentHeight
	var beginHeight uint64
	if endHeight <= stepLength {
		beginHeight = lowestHeight
	} else {
		beginHeight = endHeight - stepLength
	}
	defer func() {
		elapsed = time.Now().Sub(beginTime)
	}()
	var exitFlag = false
	var idList []string
	for !exitFlag {
		idList, _, err = c.QueryBlocks(beginHeight, endHeight)
		if err != nil {
			return
		}
		operates++
		if operates >= maxCount {
			exitFlag = true
			break
		}
		walked += len(idList)
		if lowestHeight == beginHeight {
			//loop
			endHeight = currentHeight
		} else {
			//next window
			endHeight = beginHeight - 1
		}
		if endHeight <= stepLength {
			beginHeight = lowestHeight
		} else {
			beginHeight = endHeight - stepLength
		}
	}
	return
}

func walkBlockData(c *ChainConnector, currentHeight uint64, maxCount int, stepLength uint64) (operates int, elapsed time.Duration, err error) {
	const (
		lowestHeight = 1
	)
	operates = 0
	var beginTime = time.Now()
	var endHeight = currentHeight
	var beginHeight uint64
	if endHeight <= stepLength {
		beginHeight = lowestHeight
	} else {
		beginHeight = endHeight - stepLength
	}
	defer func() {
		elapsed = time.Now().Sub(beginTime)
	}()
	var exitFlag = false
	var idList []string
	for !exitFlag {
		idList, _, err = c.QueryBlocks(beginHeight, endHeight)
		if err != nil {
			return
		}
		for _, blockID := range idList {
			_, err = c.GetBlock(blockID)
			if err != nil {
				return
			}
			operates++
			if operates >= maxCount {
				exitFlag = true
				break
			}
		}
		if lowestHeight == beginHeight {
			//loop
			endHeight = currentHeight
		} else {
			//next window
			endHeight = beginHeight - 1
		}
		if endHeight <= stepLength {
			beginHeight = lowestHeight
		} else {
			beginHeight = endHeight - stepLength
		}
	}
	return
}

func walkTransactions(c *ChainConnector, currentHeight uint64, maxCount int, stepLength uint64) (operates, processed int, elapsed time.Duration, err error) {
	const (
		lowestHeight  = 1
		recordPerPage = 20
	)
	operates = 0
	var beginTime = time.Now()
	var endHeight = currentHeight
	var beginHeight uint64
	if endHeight <= stepLength {
		beginHeight = lowestHeight
	} else {
		beginHeight = endHeight - stepLength
	}
	defer func() {
		elapsed = time.Now().Sub(beginTime)
	}()
	var idList []string
	for {
		idList, _, err = c.QueryBlocks(beginHeight, endHeight)
		if err != nil {
			return
		}
		operates++
		for _, blockID := range idList {
			var offset, total = 0, 0
			var transList []string
			var allLoaded = false
			for !allLoaded {
				if transList, offset, _, total, err = c.QueryTransactions(blockID, offset, recordPerPage); err != nil {
					return
				}
				operates++
				for _, transID := range transList {
					if _, err = c.GetTransaction(blockID, transID); err != nil {
						return
					}
					operates++
					processed++
					if processed >= maxCount {
						return
					}
				}
				offset += recordPerPage
				if offset >= total {
					allLoaded = true
					break
				}
			}
		}
		if lowestHeight == beginHeight {
			//loop
			endHeight = currentHeight
		} else {
			//next window
			endHeight = beginHeight - 1
		}
		if endHeight <= stepLength {
			beginHeight = lowestHeight
		} else {
			beginHeight = endHeight - stepLength
		}
	}
	return
}

func TestChainConnector_CRUD(t *testing.T) {
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var operates int
	var elapsed time.Duration
	if operates, elapsed, err = combineCRUD(0, client, r); err != nil {
		t.Fatalf("run crud fail: %s", err.Error())
	}
	var ms = elapsed / time.Millisecond
	var TPS = float64(operates*1000) / float64(ms)
	t.Logf("CRUD test: ok, %d opreates in %d millisecond(s), TPS %.2f", operates, ms, TPS)
}

func TestChainConnector_CreateSchema(t *testing.T) {
	const (
		propertyInt    = "p_int"
		propertyString = "p_string"
		propertyFloat  = "p_float"
	)

	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var schemaName = fmt.Sprintf("create_schema_%d", r.Intn(9999))
	var properties = []DocumentProperty{
		{
			Name: propertyInt,
			Type: PropertyTypeInteger,
		},
		{
			Name: propertyString,
			Type: PropertyTypeString,
		},
		{
			Name: propertyFloat,
			Type: PropertyTypeFloat,
		},
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	t.Logf("schema %s created", schemaName)
	if err = client.DeleteSchema(schemaName); err != nil {
		t.Fatalf("delete schema fail: %s", err.Error())
	}
	t.Logf("schema %s deleted", schemaName)
	t.Log("create schema test: ok")
}

func TestChainConnector_GetSchemaLogs(t *testing.T) {
	const (
		propertyV1 = "aaa"
		propertyV2 = "bbb"
		propertyV3 = "ccc"
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var schemaName = fmt.Sprintf("get_schema_logs_%d", r.Intn(9999))
	var propertiesV1 = []DocumentProperty{
		{
			Name: propertyV1,
			Type: PropertyTypeInteger,
		},
	}
	var propertiesV2 = []DocumentProperty{
		{
			Name: propertyV2,
			Type: PropertyTypeString,
		},
	}
	var propertiesV3 = []DocumentProperty{
		{
			Name: propertyV3,
			Type: PropertyTypeBoolean,
		},
	}
	if err = client.CreateSchema(schemaName, propertiesV1); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	t.Logf("schema %s created", schemaName)

	if err = client.UpdateSchema(schemaName, propertiesV2); err != nil {
		t.Fatalf("update schema fail: %s", err.Error())
	}
	t.Logf("schema %s updated to v2", schemaName)

	if err = client.UpdateSchema(schemaName, propertiesV3); err != nil {
		t.Fatalf("update schema fail: %s", err.Error())
	}
	t.Logf("schema %s updated to v3", schemaName)

	var fetched DocumentSchema
	if fetched, err = client.GetSchema(schemaName); err != nil {
		t.Fatalf("get schema fail: %s", err.Error())
	}
	if 1 != len(fetched.Properties) {
		t.Fatalf("unexpected property count %d", len(fetched.Properties))
	}
	var p = fetched.Properties[0]
	if propertyV3 != p.Name {
		t.Fatalf("unexpect property name %s => %s", p.Name, propertyV3)
	}
	if PropertyTypeBoolean != p.Type {
		t.Fatalf("unexpect property type %s => %s", p.Type, PropertyTypeBoolean)
	}
	var version uint64
	var logs []TraceLog
	if version, logs, err = client.GetSchemaLog(schemaName); err != nil {
		t.Fatalf("get log fail: %s", err.Error())
	}
	var expectedVersion uint64 = 3
	if expectedVersion != version {
		t.Fatalf("unexepected version %d => %d", version, expectedVersion)
	}
	t.Logf("latest version %d, %d record(s)", version, len(logs))
	var content string
	for index, record := range logs {
		if content, err = json.MarshalToString(record); err != nil {
			t.Fatalf("invalid content at record %d", index)
		}
		t.Logf("record %d: %s", index, content)
	}
	if err = client.DeleteSchema(schemaName); err != nil {
		t.Fatalf("delete schema fail: %s", err.Error())
	}
	t.Logf("schema %s deleted", schemaName)
	t.Log("get schema logs test: ok")
}

func TestChainConnector_QuerySchemas(t *testing.T) {
	const (
		schemaPrefix = "query_schemas"
		propertyName = "demo"
		schemaCount  = 5
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var totalSchemas int
	if _, _, _, totalSchemas, err = client.QuerySchemas(0, 0); err != nil {
		t.Fatalf("get system schemas fail: %s", err.Error())
	}
	t.Logf("%d schemas available before creating", totalSchemas)
	var created []string
	var properties = []DocumentProperty{
		{
			Name: propertyName,
			Type: PropertyTypeInteger,
		},
	}
	for i := 0; i < schemaCount; i++ {
		var schemaName = fmt.Sprintf("%s_%d", schemaPrefix, r.Intn(9999))
		created = append(created, schemaName)
		if err = client.CreateSchema(schemaName, properties); err != nil {
			t.Fatalf("create schema fail: %s", err.Error())
		}
	}
	var expectedCount = schemaCount + totalSchemas
	if _, _, _, totalSchemas, err = client.QuerySchemas(0, 0); err != nil {
		t.Fatalf("get all schemas fail: %s", err.Error())
	}
	if expectedCount != totalSchemas {
		t.Fatalf("expected schema count after creating %d => %d", totalSchemas, expectedCount)
	}
	t.Logf("%d schemas available after creating", totalSchemas)
	for _, schemaName := range created {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete schema fail: %s", err.Error())
		}
		t.Logf("schema %s deleted", schemaName)
	}
	expectedCount = totalSchemas - schemaCount
	if _, _, _, totalSchemas, err = client.QuerySchemas(0, 0); err != nil {
		t.Fatalf("get all schemas fail: %s", err.Error())
	}
	if expectedCount != totalSchemas {
		t.Fatalf("expected schema count after deleting %d => %d", totalSchemas, expectedCount)
	}
	t.Logf("%d schemas available after deleting", totalSchemas)
	t.Log("query schemas test: ok")
}

func TestChainConnector_QueryMassSchemas(t *testing.T) {
	const (
		schemaPrefix = "query_mass_schemas"
		propertyName = "demo"
		schemaCount  = 5000
		queryCount   = 100
		maxRecord    = 70
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var schemaNames, created []string
	var properties = []DocumentProperty{
		{
			Name: propertyName,
			Type: PropertyTypeInteger,
		},
	}
	var offset, total int
	if schemaNames, offset, _, total, err = client.QuerySchemas(0, 0); err != nil {
		t.Fatalf("get current schemas fail: %s", err.Error())
	}
	var expectedTotal = total + schemaCount
	var exists bool
	for i := 0; i < schemaCount; i++ {
		var schemaName = fmt.Sprintf("%s_%d", schemaPrefix, r.Intn(99999999))
		if exists, err = client.HasSchema(schemaName); err != nil {
			t.Fatalf("check schema fail: %s", err.Error())
		} else if exists {
			if err = client.DeleteSchema(schemaName); err != nil {
				t.Fatalf("delete previous schema %s fail: %s", schemaName, err.Error())
			}
			expectedTotal--
			t.Logf("delete previous schema %s deleted", schemaName)
		}
		if err = client.CreateSchema(schemaName, properties); err != nil {
			t.Fatalf("create schema fail: %s", err.Error())
		}
		created = append(created, schemaName)
	}
	defer func() {
		for _, schemaName := range created {
			if err = client.DeleteSchema(schemaName); err != nil {
				t.Fatalf("delete schema fail: %s", err.Error())
			}
			//t.Logf("schema %s deleted", schemaName)
		}
	}()

	var beginTime = time.Now()
	offset = 0
	for i := 0; i < queryCount; i++ {
		if schemaNames, _, _, total, err = client.QuerySchemas(offset, maxRecord); err != nil {
			t.Fatalf("get all schemas fail: %s", err.Error())
		}
		if expectedTotal != total {
			t.Fatalf("unexpected total count %d => %d", total, expectedTotal)
		}
		var count = len(schemaNames)
		var expectedCount = maxRecord
		if total-offset < maxRecord {
			expectedCount = total - offset
		}
		if expectedCount != count {
			t.Fatalf("unexpected record count %d => %d from %d", count, expectedCount, offset)
		}
		t.Logf("%d / %d schemas from offset %d returned",
			count, total, offset)
		offset += maxRecord
		if offset >= total {
			offset = 0
		}
	}
	var elapsed = time.Now().Sub(beginTime) / time.Millisecond
	var TPS = float64(queryCount*1000) / float64(elapsed)
	t.Logf("query mass schema test: ok, %d queries(%d schemas) executed in %d milliseconds, TPS %.2f",
		queryCount, schemaCount, elapsed, TPS)
}

func TestChainConnector_QueryMassiveDocuments(t *testing.T) {
	const (
		schemaPrefix      = "query_mass_documents"
		propertyI         = "demo_int"
		propertyF         = "demo_float"
		docCount          = 10000
		intThreshold      = 6
		floatMinThreshold = 9.9
		floatMaxThreshold = 999.99
		queryCount        = 100
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var properties = []DocumentProperty{
		{
			Name: propertyI,
			Type: PropertyTypeInteger,
		},
		{
			Name: propertyF,
			Type: PropertyTypeFloat,
		},
	}
	var schemaName = fmt.Sprintf("%s_%d", schemaPrefix, r.Intn(99999999))
	var exists = false
	if exists, err = client.HasSchema(schemaName); err != nil {
		t.Fatalf("check schema fail: %s", err.Error())
	} else if exists {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete previous schema %s fail: %s", schemaName, err.Error())
		}
		t.Logf("delete previous schema %s deleted", schemaName)
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete schema fail: %s", err.Error())
		}
	}()
	type testDoc struct {
		DemoInt   int     `json:"demo_int"`
		DemoFloat float64 `json:"demo_float"`
	}
	for i := 0; i < docCount; i++ {
		var docID = fmt.Sprintf("%s_doc_%d", schemaPrefix, i)
		var doc = testDoc{
			DemoInt:   i,
			DemoFloat: 10100 - float64(i)*12.34,
		}
		var content string
		if content, err = json.MarshalToString(doc); err != nil {
			t.Fatalf("generate doc content fail: %s", err.Error())
		}
		if _, err = client.AddDocument(schemaName, docID, content); err != nil {
			t.Fatalf("create doc fail: %s", err.Error())
		}
	}
	t.Logf("%d doc created with schema %s", docCount, schemaName)

	var condition QueryCondition
	condition.
		PropertyGreaterOrEqual(propertyI, strconv.Itoa(intThreshold)).
		PropertyGreaterThan(propertyF, fmt.Sprintf("%f", floatMinThreshold)).
		PropertyLessThan(propertyF, fmt.Sprintf("%f", floatMaxThreshold))

	var docs []Document
	var recordLimit, offset, totalRecord = 0, 0, 0
	var beginTime = time.Now()
	if docs, recordLimit, offset, totalRecord, err = client.QueryDocuments(schemaName, condition); err != nil {
		t.Fatalf("query documents fail: %s", err.Error())
	}
	var count = len(docs)
	t.Logf("%d / %d documents returned, offset %d, limit %d", count, totalRecord, offset, recordLimit)

	var elapsed = time.Now().Sub(beginTime) / time.Millisecond
	var TPS = float64(queryCount*1000) / float64(elapsed)
	t.Logf("query mass doc test: ok, %d queries(%d documents) executed in %d milliseconds, TPS %.2f",
		queryCount, docCount, elapsed, TPS)
}

func TestChainConnector_QueryMassiveIndexedDocuments(t *testing.T) {
	const (
		schemaPrefix      = "query_mass_documents"
		propertyI         = "demo_int"
		propertyF         = "demo_float"
		docCount          = 10000
		intThreshold      = 6
		floatMinThreshold = 9.9
		floatMaxThreshold = 999.99
		queryCount        = 100
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var properties = []DocumentProperty{
		{
			Name:    propertyI,
			Type:    PropertyTypeInteger,
			Indexed: true,
		},
		{
			Name:    propertyF,
			Type:    PropertyTypeFloat,
			Indexed: true,
		},
	}
	var schemaName = fmt.Sprintf("%s_%d", schemaPrefix, r.Intn(99999999))
	var exists = false
	if exists, err = client.HasSchema(schemaName); err != nil {
		t.Fatalf("check schema fail: %s", err.Error())
	} else if exists {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete previous schema %s fail: %s", schemaName, err.Error())
		}
		t.Logf("delete previous schema %s deleted", schemaName)
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete schema fail: %s", err.Error())
		}
	}()
	type testDoc struct {
		DemoInt   int     `json:"demo_int"`
		DemoFloat float64 `json:"demo_float"`
	}
	for i := 0; i < docCount; i++ {
		var docID = fmt.Sprintf("%s_doc_%d", schemaPrefix, i)
		var doc = testDoc{
			DemoInt:   i,
			DemoFloat: 10100 - float64(i)*12.34,
		}
		var content string
		if content, err = json.MarshalToString(doc); err != nil {
			t.Fatalf("generate doc content fail: %s", err.Error())
		}
		if _, err = client.AddDocument(schemaName, docID, content); err != nil {
			t.Fatalf("create doc fail: %s", err.Error())
		}
	}
	t.Logf("%d doc created with schema %s", docCount, schemaName)

	var condition QueryCondition
	condition.
		PropertyGreaterOrEqual(propertyI, strconv.Itoa(intThreshold)).
		PropertyGreaterThan(propertyF, fmt.Sprintf("%f", floatMinThreshold)).
		PropertyLessThan(propertyF, fmt.Sprintf("%f", floatMaxThreshold))

	var docs []Document
	var recordLimit, offset, totalRecord = 0, 0, 0
	var beginTime = time.Now()
	if docs, recordLimit, offset, totalRecord, err = client.QueryDocuments(schemaName, condition); err != nil {
		t.Fatalf("query documents fail: %s", err.Error())
	}
	var count = len(docs)
	t.Logf("%d / %d documents returned, offset %d, limit %d", count, totalRecord, offset, recordLimit)

	var elapsed = time.Now().Sub(beginTime) / time.Millisecond
	var TPS = float64(queryCount*1000) / float64(elapsed)
	t.Logf("query mass indexed doc test: ok, %d queries(%d documents) executed in %d milliseconds, TPS %.2f",
		queryCount, docCount, elapsed, TPS)
}

func TestChainConnector_Actors(t *testing.T) {
	defer clearClientEnvironment()
	conn, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	const schemaName = "test-schema-actors"
	var exists bool
	{
		if exists, err = conn.HasSchema(schemaName); err != nil {
			t.Fatalf("check schema fail: %s", err.Error())
		}
		if exists {
			if err = conn.DeleteSchema(schemaName); err != nil {
				t.Fatalf("delete previous schema %s fail: %s", schemaName, err.Error())
			}
			t.Logf("previous schema %s deleted", schemaName)
		}
		var properties = []DocumentProperty{
			{
				Name: "name",
				Type: PropertyTypeString,
			},
			{
				Name: "age",
				Type: PropertyTypeInteger,
			},
			{
				Name: "available",
				Type: PropertyTypeBoolean,
			},
		}
		err = conn.CreateSchema(schemaName, properties)
	}
	var actors []ActorPrivileges
	if actors, err = conn.GetSchemaActors(schemaName); err != nil {
		t.Fatalf("get schema actors fail: %s", err.Error())
	}
	if 0 == len(actors) {
		t.Fatal("no actor available in schema")
	}
	var currentGroup = actors[0].Group
	var actorConfigure = []ActorPrivileges{
		{
			Group:    currentGroup,
			Owner:    true,
			Executor: true,
			Updater:  true,
			Viewer:   true,
		},
		{
			Group:    "audit",
			Owner:    false,
			Executor: false,
			Updater:  false,
			Viewer:   true,
		},
		{
			Group:    "runner",
			Owner:    false,
			Executor: true,
			Updater:  true,
			Viewer:   true,
		},
	}
	if err = conn.UpdateSchemaActors(schemaName, actorConfigure); err != nil {
		t.Fatalf("update schema actors fail: %s", err.Error())
	}
	var docID string
	{
		//add a document
		var content = "{\"name\": \"hello\", \"age\": 20, \"available\": true}"
		docID, err = conn.AddDocument(schemaName, "", content)
		if err = conn.UpdateDocumentActors(schemaName, docID, actorConfigure); err != nil {
			t.Fatalf("update doc actors fail: %s", err.Error())
		}
		if actors, err = conn.GetDocumentActors(schemaName, docID); err != nil {
			t.Fatalf("get doc actors fail: %s", err.Error())
		}
		var output string
		if output, err = json.MarshalToString(actors); err != nil {
			t.Fatalf("marshal doc actors fail: %s", err.Error())
		}
		t.Logf("updated doc actors:\n%s\n", output)
	}
	{
		var define = ContractDefine{
			Steps: []ContractStep{
				{
					Action: "delete_doc",
					Params: []string{"@1", "@2"},
				},
				{
					Action: "submit",
				},
			},
		}
		var contractName = schemaName
		if exists, err = conn.HasContract(contractName); err != nil {
			t.Fatalf("check contract fail: %s", err.Error())
		} else if exists {
			if err = conn.WithdrawContract(contractName); err != nil {
				t.Fatalf("withdraw previous contract %s fail: %s", contractName, err.Error())
			}
		}
		if err = conn.DeployContract(contractName, define); err != nil {
			t.Fatalf("deploy contract fail: %s", err.Error())
		}
		if err = conn.UpdateContractActors(contractName, actorConfigure); err != nil {
			t.Fatalf("update contract actors fail: %s", err.Error())
		}
		if actors, err = conn.GetContractActors(contractName); err != nil {
			t.Fatalf("get contract actors fail: %s", err.Error())
		}
		var output string
		if output, err = json.MarshalToString(actors); err != nil {
			t.Fatalf("marshal contract actors fail: %s", err.Error())
		}
		t.Logf("updated contract actors:\n%s\n", output)
	}
	if err = conn.DeleteSchema(schemaName); err != nil {
		t.Fatalf("delete schema fail: %s", err.Error())
	}
	t.Log("Test actor functions: pass")
}

func TestChainConnector_DocumentOperates(t *testing.T) {
	type testDocument struct {
		IntProperty    int     `json:"int_property"`
		BoolProperty   bool    `json:"bool_property"`
		StringProperty string  `json:"string_property"`
		FloatProperty  float64 `json:"float_property"`
	}

	const (
		IntProperty    = "int_property"
		BoolProperty   = "bool_property"
		StringProperty = "string_property"
		FloatProperty  = "float_property"
		intValueV2     = 2
		boolValueV2    = true
		stringValueV2  = "hello"
		floatValueV2   = 3.55
		intValueV3     = 9
		boolValueV3    = false
		stringValueV3  = "some sample text"
		floatValueV3   = 9.457
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("document_operates_%d", r.Intn(9999))
	var properties = []DocumentProperty{
		{
			Name: IntProperty,
			Type: PropertyTypeInteger,
		},
		{
			Name: BoolProperty,
			Type: PropertyTypeBoolean,
		},
		{
			Name: StringProperty,
			Type: PropertyTypeString,
		},
		{
			Name: FloatProperty,
			Type: PropertyTypeFloat,
		},
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete schema fail: %s", err.Error())
		}
		t.Logf("schema '%s' deleted", schemaName)
	}()
	var doc = testDocument{
		IntProperty:    0,
		BoolProperty:   false,
		StringProperty: "",
		FloatProperty:  0,
	}
	var data string
	if data, err = json.MarshalToString(doc); err != nil {
		t.Fatalf("marshal content fail: %s", err.Error())
	}
	var docID string
	if docID, err = client.AddDocument(schemaName, docID, data); err != nil {
		t.Fatalf("add document fail: %s", err.Error())
	}
	defer func() {
		if err = client.RemoveDocument(schemaName, docID); err != nil {
			t.Fatalf("remove document fail: %s", err.Error())
		}
		t.Logf("document '%s.%s' removed", schemaName, docID)
	}()
	t.Logf("document %s added", docID)
	var expectedVersion uint64 = 1
	doc.IntProperty = intValueV2
	doc.StringProperty = stringValueV2
	doc.BoolProperty = boolValueV2
	doc.FloatProperty = floatValueV2
	if data, err = json.MarshalToString(doc); err != nil {
		t.Fatalf("marshal content v2 fail: %s", err.Error())
	}
	if err = client.UpdateDocument(schemaName, docID, data); err != nil {
		t.Fatalf("update document fail: %s", err.Error())
	}
	expectedVersion++
	var v2 testDocument
	if data, err = client.GetDocument(schemaName, docID); err != nil {
		t.Fatalf("get document fail: %s", err.Error())
	}
	if err = json.UnmarshalFromString(data, &v2); err != nil {
		t.Fatalf("unmarshal content v2 fail: %s", err.Error())
	}
	if v2.BoolProperty != boolValueV2 {
		t.Fatalf("unexpected bool value of v2 %t => %t", v2.BoolProperty, boolValueV2)
	}
	if v2.IntProperty != intValueV2 {
		t.Fatalf("unexpected int value of v2 %d => %d", v2.IntProperty, intValueV2)
	}
	if v2.StringProperty != stringValueV2 {
		t.Fatalf("unexpected string value of v2 %s => %s", v2.StringProperty, stringValueV2)
	}
	if v2.FloatProperty != floatValueV2 {
		t.Fatalf("unexpected float value of v2 %f => %f", v2.FloatProperty, floatValueV2)
	}
	t.Log("document updated to v2")
	//v3
	if err = client.UpdateDocumentProperty(schemaName, docID, IntProperty, PropertyTypeInteger, intValueV3); err != nil {
		t.Fatalf("update int property fail: %s", err.Error())
	}
	expectedVersion++
	if err = client.UpdateDocumentProperty(schemaName, docID, StringProperty, PropertyTypeString, stringValueV3); err != nil {
		t.Fatalf("update string property fail: %s", err.Error())
	}
	expectedVersion++
	if err = client.UpdateDocumentProperty(schemaName, docID, BoolProperty, PropertyTypeBoolean, boolValueV3); err != nil {
		t.Fatalf("update bool property fail: %s", err.Error())
	}
	expectedVersion++
	if err = client.UpdateDocumentProperty(schemaName, docID, FloatProperty, PropertyTypeFloat, floatValueV3); err != nil {
		t.Fatalf("update float property fail: %s", err.Error())
	}
	expectedVersion++
	var v3 testDocument
	if data, err = client.GetDocument(schemaName, docID); err != nil {
		t.Fatalf("get document v3 fail: %s", err.Error())
	}
	if err = json.UnmarshalFromString(data, &v3); err != nil {
		t.Fatalf("unmarshal content v3 fail: %s", err.Error())
	}
	if v3.BoolProperty != boolValueV3 {
		t.Fatalf("unexpected bool value of v3 %t => %t", v3.BoolProperty, boolValueV3)
	}
	if v3.IntProperty != intValueV3 {
		t.Fatalf("unexpected int value of v3 %d => %d", v3.IntProperty, intValueV3)
	}
	if v3.StringProperty != stringValueV3 {
		t.Fatalf("unexpected string value of v3 %s => %s", v3.StringProperty, stringValueV3)
	}
	if v3.FloatProperty != floatValueV3 {
		t.Fatalf("unexpected float value of v3 %f => %f", v3.FloatProperty, floatValueV3)
	}
	t.Log("document updated to v3")
	var version uint64
	var records []TraceLog
	if version, records, err = client.GetDocumentLog(schemaName, docID); err != nil {
		t.Fatalf("get document records fail: %s", err.Error())
	}
	if expectedVersion != version {
		t.Fatalf("unexpected version %d => %d", version, expectedVersion)
	}
	t.Logf("current version %d, %d records", version, len(records))
	var content string
	for index, record := range records {
		if content, err = json.MarshalToString(record); err != nil {
			t.Fatalf("invalid content at record %d", index)
		}
		t.Logf("record %d: %s", index, content)
	}
	t.Log("document operates test: ok")
}

func TestChainConnector_ErrorResult(t *testing.T) {
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var properties = []DocumentProperty{
		{
			Name: "sample",
			Type: PropertyTypeInteger,
		},
	}

	var schemaName = fmt.Sprintf("err_result_%d", r.Intn(9999))
	if err = client.CreateSchema(schemaName, properties); nil != err {
		t.Fatalf("create first schema fail: %s", err.Error())
	}
	defer client.DeleteSchema(schemaName)
	if err = client.CreateSchema(schemaName, properties); nil == err {
		t.Fatal("create schema not fail")
	}
	t.Logf("create schema fail: %s", err.Error())
	if _, err = client.AddDocument("invalid", "aaa", ""); nil == err {
		t.Fatal("add doc not fail")
	}
	t.Logf("add doc fail: %s", err.Error())

	t.Log("error result test: ok")
}

func TestChainConnector_HasSchemaAndDocument(t *testing.T) {
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var properties = []DocumentProperty{
		{
			Name: "sample",
			Type: PropertyTypeInteger,
		},
	}

	var schemaName = fmt.Sprintf("check_schema_and_doc_%d", r.Intn(9999))
	var exists bool
	if exists, err = client.HasSchema(schemaName); nil != err {
		t.Fatalf("check schema first fail: %s", err.Error())
	}
	if exists {
		t.Fatalf("schema '%s' exists", schemaName)
	}
	t.Logf("schema '%s' not exists", schemaName)
	if err = client.CreateSchema(schemaName, properties); nil != err {
		t.Fatalf("create first schema fail: %s", err.Error())
	}
	if exists, err = client.HasSchema(schemaName); nil != err {
		t.Fatalf("check schema second fail: %s", err.Error())
	}
	if !exists {
		t.Fatalf("schema '%s' not exists", schemaName)
	}
	t.Logf("schema '%s' exists", schemaName)
	defer client.DeleteSchema(schemaName)

	const docID = "aaa"
	if exists, err = client.HasDocument(schemaName, docID); nil != err {
		t.Fatalf("check doc first fail: %s", err.Error())
	}
	if exists {
		t.Fatalf("doc '%s.%s' exists", schemaName, docID)
	}
	t.Logf("doc '%s.%s' not exists", schemaName, docID)
	if _, err = client.AddDocument(schemaName, docID, "{\"sample\": 1}"); nil != err {

		t.Fatalf("add doc fail: %s", err.Error())
	}
	t.Log("add doc success")
	if exists, err = client.HasDocument(schemaName, docID); nil != err {
		t.Fatalf("check doc '%s.%s' second fail: %s", schemaName, docID, err.Error())
	}
	if !exists {
		t.Fatalf("doc '%s.%s' not exists", schemaName, docID)
	}
	t.Logf("doc '%s.%s' exists", schemaName, docID)
	t.Log("check schema and doc test: ok")
}

func TestChainConnector_QueryDocumentsFilteredByMultiProperties(t *testing.T) {
	const (
		stringProperty    = "s"
		intProperty       = "i"
		floatProperty     = "f"
		boolProperty      = "b"
		total             = 30
		limit             = 5
		beginOffset       = 1
		intThreshold      = 6
		floatMinThreshold = 9.9
		floatMaxThreshold = 90.0
		boolThreshold     = true
		stringThreshold   = "aaa"
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("query_docs_%d", r.Intn(9999))
	var schema = DocumentSchema{
		Name: schemaName,
		Properties: []DocumentProperty{
			{
				Name: stringProperty,
				Type: PropertyTypeString,
			},
			{
				Name: intProperty,
				Type: PropertyTypeInteger,
			},
			{
				Name: floatProperty,
				Type: PropertyTypeFloat,
			},
			{
				Name: boolProperty,
				Type: PropertyTypeBoolean,
			},
		},
	}
	if err = client.CreateSchema(schema.Name, schema.Properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	for i := 0; i < total; i++ {
		var content = "{}"
		if content, err = sjson.Set(content, intProperty, i); err != nil {
			t.Fatalf("set integer for doc fail: %s", err.Error())
		}
		if content, err = sjson.Set(content, floatProperty, float64(i)*2.22); err != nil {
			t.Fatalf("set float for doc fail: %s", err.Error())
		}
		if 0 == i%2 {
			if content, err = sjson.Set(content, boolProperty, true); err != nil {
				t.Fatalf("set boolean for doc fail: %s", err.Error())
			}
		} else {
			if content, err = sjson.Set(content, boolProperty, false); err != nil {
				t.Fatalf("set boolean for doc fail: %s", err.Error())
			}
		}
		if 0 == i%3 {
			if content, err = sjson.Set(content, stringProperty, ""); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		} else if 1 == i%3 {
			if content, err = sjson.Set(content, stringProperty, stringThreshold); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		} else {
			if content, err = sjson.Set(content, stringProperty, "bbb"); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		}
		if _, err = client.AddDocument(schemaName, "", content); err != nil {
			t.Fatalf("add document fail: %s", err.Error())
		}
	}
	//check pagination
	var condition QueryCondition
	condition.
		MaxRecord(limit).
		SetOffset(beginOffset).
		PropertyGreaterOrEqual(intProperty, strconv.Itoa(intThreshold)).
		PropertyGreaterThan(floatProperty, fmt.Sprintf("%f", floatMinThreshold)).
		PropertyLessThan(floatProperty, fmt.Sprintf("%f", floatMaxThreshold)).
		PropertyEqual(boolProperty, strconv.FormatBool(boolThreshold)).
		PropertyEqual(stringProperty, stringThreshold)

	var docs []Document
	var recordLimit, offset, totalRecord = 0, 0, 0
	if docs, recordLimit, offset, totalRecord, err = client.QueryDocuments(schemaName, condition); err != nil {
		t.Fatalf("query documents fail: %s", err.Error())
	}
	var docCount = len(docs)
	t.Logf("%d / %d documents returned, offset %d, limit %d", docCount, totalRecord, offset, recordLimit)

	for index := 0; index < docCount; index++ {
		var doc = docs[index]
		var content = []byte(doc.Content)
		var intValue = json.Get(content, intProperty).ToInt()
		if intValue < intThreshold {
			t.Fatalf("unexpected int property %d at doc %d, must >= %d", intValue, index, intThreshold)
		}
		var floatValue = json.Get(content, floatProperty).ToFloat64()
		if floatValue < floatMinThreshold || floatValue > floatMaxThreshold {
			t.Fatalf("unexpected float property %f at doc %d, must between (%f, %f)",
				floatValue, index, floatMinThreshold, floatMaxThreshold)
		}
		var boolValue = json.Get(content, boolProperty).ToBool()
		if boolValue != boolThreshold {
			t.Fatalf("unexpected bool property %t at doc %d, must be %t", boolValue, index, boolThreshold)
		}
		var stringValue = json.Get(content, stringProperty).ToString()
		if stringValue != stringThreshold {
			t.Fatalf("unexpected string property %s at doc %d, must be %s", stringValue, index, stringThreshold)
		}
		t.Logf("%dth doc '%s' (offset %d), properties: int %d, float %f, string %s, bool %t",
			index, doc.ID, index+beginOffset, intValue, floatValue, stringValue, boolValue)
	}
	t.Log("query documents filtered by multi properties: ok")
}

func TestChainConnector_QueryIndexedDocumentsFilteredByMultiProperties(t *testing.T) {
	const (
		stringProperty    = "s"
		intProperty       = "i"
		floatProperty     = "f"
		boolProperty      = "b"
		total             = 30
		limit             = 5
		beginOffset       = 1
		intThreshold      = 6
		floatMinThreshold = 9.9
		floatMaxThreshold = 90.0
		boolThreshold     = true
		stringThreshold   = "aaa"
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("query_docs_%d", r.Intn(9999))
	var schema = DocumentSchema{
		Name: schemaName,
		Properties: []DocumentProperty{
			{
				Name:    stringProperty,
				Type:    PropertyTypeString,
				Indexed: true,
			},
			{
				Name:    intProperty,
				Type:    PropertyTypeInteger,
				Indexed: true,
			},
			{
				Name:    floatProperty,
				Type:    PropertyTypeFloat,
				Indexed: true,
			},
			{
				Name:    boolProperty,
				Type:    PropertyTypeBoolean,
				Indexed: true,
			},
		},
	}
	if err = client.CreateSchema(schema.Name, schema.Properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	for i := 0; i < total; i++ {
		var content = "{}"
		if content, err = sjson.Set(content, intProperty, i); err != nil {
			t.Fatalf("set integer for doc fail: %s", err.Error())
		}
		if content, err = sjson.Set(content, floatProperty, float64(i)*2.22); err != nil {
			t.Fatalf("set float for doc fail: %s", err.Error())
		}
		if 0 == i%2 {
			if content, err = sjson.Set(content, boolProperty, true); err != nil {
				t.Fatalf("set boolean for doc fail: %s", err.Error())
			}
		} else {
			if content, err = sjson.Set(content, boolProperty, false); err != nil {
				t.Fatalf("set boolean for doc fail: %s", err.Error())
			}
		}
		if 0 == i%3 {
			if content, err = sjson.Set(content, stringProperty, ""); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		} else if 1 == i%3 {
			if content, err = sjson.Set(content, stringProperty, stringThreshold); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		} else {
			if content, err = sjson.Set(content, stringProperty, "bbb"); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		}
		if _, err = client.AddDocument(schemaName, "", content); err != nil {
			t.Fatalf("add document fail: %s", err.Error())
		}
	}
	//check pagination
	var condition QueryCondition
	condition.
		MaxRecord(limit).
		SetOffset(beginOffset).
		PropertyGreaterOrEqual(intProperty, strconv.Itoa(intThreshold)).
		PropertyGreaterThan(floatProperty, fmt.Sprintf("%f", floatMinThreshold)).
		PropertyLessThan(floatProperty, fmt.Sprintf("%f", floatMaxThreshold)).
		PropertyEqual(boolProperty, strconv.FormatBool(boolThreshold)).
		PropertyEqual(stringProperty, stringThreshold)

	var docs []Document
	var recordLimit, offset, totalRecord = 0, 0, 0
	if docs, recordLimit, offset, totalRecord, err = client.QueryDocuments(schemaName, condition); err != nil {
		t.Fatalf("query documents fail: %s", err.Error())
	}
	var docCount = len(docs)
	t.Logf("%d / %d documents returned, offset %d, limit %d", docCount, totalRecord, offset, recordLimit)

	for index := 0; index < docCount; index++ {
		var doc = docs[index]
		var content = []byte(doc.Content)
		var intValue = json.Get(content, intProperty).ToInt()
		if intValue < intThreshold {
			t.Fatalf("unexpected int property %d at doc %d, must >= %d", intValue, index, intThreshold)
		}
		var floatValue = json.Get(content, floatProperty).ToFloat64()
		if floatValue < floatMinThreshold || floatValue > floatMaxThreshold {
			t.Fatalf("unexpected float property %f at doc %d, must between (%f, %f)",
				floatValue, index, floatMinThreshold, floatMaxThreshold)
		}
		var boolValue = json.Get(content, boolProperty).ToBool()
		if boolValue != boolThreshold {
			t.Fatalf("unexpected bool property %t at doc %d, must be %t", boolValue, index, boolThreshold)
		}
		var stringValue = json.Get(content, stringProperty).ToString()
		if stringValue != stringThreshold {
			t.Fatalf("unexpected string property %s at doc %d, must be %s", stringValue, index, stringThreshold)
		}
		t.Logf("%dth doc '%s' (offset %d), properties: int %d, float %f, string %s, bool %t",
			index, doc.ID, index+beginOffset, intValue, floatValue, stringValue, boolValue)
	}
	t.Log("query indexed documents filtered by multi properties: ok")
}

func TestChainConnector_RebuildIndex(t *testing.T) {
	const ()
	type car struct {
		Brand     string `json:"brand"`
		Year      int    `json:"year"`
		Color     string `json:"color"`
		Available bool   `json:"available"`
	}
	type testItem struct {
		ID  string
		Car car
	}
	type queryCase struct {
		Name     string
		Query    *QueryCondition
		Expected []string
	}
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("rebuild_index_%d", r.Intn(99999999))
	var testData = []testItem{
		{
			ID: "1",
			Car: car{
				Brand:     "toyota",
				Year:      1998,
				Color:     "white",
				Available: true,
			},
		},
		{
			ID: "2",
			Car: car{
				Brand:     "toyota",
				Year:      2008,
				Color:     "black",
				Available: true,
			},
		},
		{
			ID: "3",
			Car: car{
				Brand:     "toyota",
				Year:      2010,
				Color:     "white",
				Available: true,
			},
		},
		{
			ID: "4",
			Car: car{
				Brand:     "toyota",
				Year:      2020,
				Color:     "grey",
				Available: true,
			},
		},
		{
			ID: "5",
			Car: car{
				Brand:     "tesla",
				Year:      2019,
				Color:     "white",
				Available: true,
			},
		},
		{
			ID: "6",
			Car: car{
				Brand:     "tesla",
				Year:      2020,
				Color:     "black",
				Available: false,
			},
		},
		{
			ID: "7",
			Car: car{
				Brand:     "tesla",
				Year:      2021,
				Color:     "black",
				Available: true,
			},
		},
		{
			ID: "8",
			Car: car{
				Brand:     "audi",
				Year:      2018,
				Color:     "black",
				Available: true,
			},
		},
		{
			ID: "9",
			Car: car{
				Brand:     "audi",
				Year:      2017,
				Color:     "black",
				Available: true,
			},
		},
		{
			ID: "10",
			Car: car{
				Brand:     "audi",
				Year:      2016,
				Color:     "white",
				Available: true,
			},
		},
	}
	var cases = []queryCase{
		{
			Name:     "brand == 'toyota'",
			Query:    new(QueryCondition).PropertyEqual("brand", "toyota"),
			Expected: []string{"1", "2", "3", "4"},
		},
		{
			Name: "brand != 'toyota' && 2017 < year < 2021, ascend by year",
			Query: new(QueryCondition).
				PropertyNotEqual("brand", "toyota").
				PropertyGreaterThan("year", "2017").
				PropertyLessThan("year", "2021").
				AscendBy("year"),
			Expected: []string{"8", "5", "6"},
		},
		{
			Name: "color != 'white' && 2019 <= year && available != true",
			Query: new(QueryCondition).
				PropertyNotEqual("color", "white").
				PropertyGreaterOrEqual("year", "2019").
				PropertyNotEqual("available", "true"),
			Expected: []string{"6"},
		},
	}

	var doTest = func(cases []queryCase) {
		for index, testCase := range cases {
			t.Logf("begin case-%d: %s", index, testCase.Name)
			var docs []Document
			var total int
			if docs, _, _, total, err = client.QueryDocuments(schemaName, *testCase.Query); err != nil {
				t.Fatalf("run case-%d on fail: %s", index, err.Error())
			}
			var idList []string
			for _, doc := range docs {
				idList = append(idList, doc.ID)
			}
			var resultCount = len(idList)
			if resultCount != len(testCase.Expected) {
				t.Fatalf("unexpected result count %d [ %s ]=> %d [ %s ]",
					resultCount, strings.Join(idList, ","),
					len(testCase.Expected), strings.Join(testCase.Expected, ","))
			}
			for i := 0; i < resultCount; i++ {
				if idList[i] != testCase.Expected[i] {
					t.Fatalf("%dth elmenet not equal: %s / [ %s ] => %s / [ %s ]",
						i, idList, strings.Join(idList, ","),
						testCase.Expected[i], strings.Join(testCase.Expected, ","))
				}
			}
			t.Logf("case-%d passed: %d / %d returned with [ %s ]",
				index, resultCount, total, strings.Join(idList, ","))
		}
	}

	{
		//noindex
		var schema = DocumentSchema{
			Name: schemaName,
			Properties: []DocumentProperty{
				{
					Name: "brand",
					Type: PropertyTypeString,
				},
				{
					Name: "year",
					Type: PropertyTypeInteger,
				},
				{
					Name: "color",
					Type: PropertyTypeString,
				},
				{
					Name: "available",
					Type: PropertyTypeBoolean,
				},
			},
		}
		if err = client.CreateSchema(schema.Name, schema.Properties); err != nil {
			t.Fatalf("create schema fail: %s", err.Error())
		}
		defer func() {
			client.DeleteSchema(schemaName)
		}()
		for _, item := range testData {
			var content string
			if content, err = json.MarshalToString(item.Car); err != nil {
				t.Fatalf("marshal content fail: %s", err.Error())
			}
			if _, err = client.AddDocument(schemaName, item.ID, content); err != nil {
				t.Fatalf("add doc '%s' fail: %s", item.ID, err.Error())
			}
		}
		t.Logf("%d documents created", len(testData))
		t.Logf("begin test noindex query with %d cases", len(cases))
		doTest(cases)
	}
	{
		//rebuild all
		var schema = DocumentSchema{
			Name: schemaName,
			Properties: []DocumentProperty{
				{
					Name:    "brand",
					Type:    PropertyTypeString,
					Indexed: true,
				},
				{
					Name:    "year",
					Type:    PropertyTypeInteger,
					Indexed: true,
				},
				{
					Name:    "color",
					Type:    PropertyTypeString,
					Indexed: true,
				},
				{
					Name:    "available",
					Type:    PropertyTypeBoolean,
					Indexed: true,
				},
			},
		}
		if err = client.UpdateSchema(schema.Name, schema.Properties); err != nil {
			t.Fatalf("update schema fail: %s", err.Error())
		}
		if err = client.RebuildIndex(schemaName); err != nil {
			t.Fatalf("rebuild full index fail: %s", err.Error())
		}
		t.Logf("begin test full index query with %d cases", len(cases))
		doTest(cases)
	}

	{
		//partial rebuild
		var schema = DocumentSchema{
			Name: schemaName,
			Properties: []DocumentProperty{
				{
					Name:    "brand",
					Type:    PropertyTypeString,
					Indexed: true,
				},
				{
					Name:    "year",
					Type:    PropertyTypeInteger,
					Indexed: true,
				},
				{
					Name:    "color",
					Type:    PropertyTypeString,
					Indexed: true,
				},
				{
					Name: "available",
					Type: PropertyTypeBoolean,
				},
			},
		}
		if err = client.UpdateSchema(schema.Name, schema.Properties); err != nil {
			t.Fatalf("update schema fail: %s", err.Error())
		}
		if err = client.RebuildIndex(schemaName); err != nil {
			t.Fatalf("rebuild partial index fail: %s", err.Error())
		}
		t.Logf("begin test partial index query with %d cases", len(cases))
		doTest(cases)
	}
	t.Log("test rebuilding: ok")
}

func TestChainConnector_QueryDocumentsFilteredByMultiPropertiesWithOrder(t *testing.T) {
	const (
		stringProperty    = "s"
		intProperty       = "i"
		floatProperty     = "f"
		boolProperty      = "b"
		total             = 30
		limit             = 5
		beginOffset       = 1
		intThreshold      = 6
		floatMinThreshold = 9.9
		floatMaxThreshold = 90.0
		boolThreshold     = true
		stringThreshold   = "aaa"
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("query_docs_%d", r.Intn(9999))
	var schema = DocumentSchema{
		Name: schemaName,
		Properties: []DocumentProperty{
			{
				Name: stringProperty,
				Type: PropertyTypeString,
			},
			{
				Name: intProperty,
				Type: PropertyTypeInteger,
			},
			{
				Name: floatProperty,
				Type: PropertyTypeFloat,
			},
			{
				Name: boolProperty,
				Type: PropertyTypeBoolean,
			},
		},
	}
	if err = client.CreateSchema(schema.Name, schema.Properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	for i := 0; i < total; i++ {
		var content = "{}"
		if content, err = sjson.Set(content, intProperty, i); err != nil {
			t.Fatalf("set integer for doc fail: %s", err.Error())
		}
		if content, err = sjson.Set(content, floatProperty, float64(i)*2.22); err != nil {
			t.Fatalf("set float for doc fail: %s", err.Error())
		}
		if 0 == i%2 {
			if content, err = sjson.Set(content, boolProperty, true); err != nil {
				t.Fatalf("set boolean for doc fail: %s", err.Error())
			}
		} else {
			if content, err = sjson.Set(content, boolProperty, false); err != nil {
				t.Fatalf("set boolean for doc fail: %s", err.Error())
			}
		}
		if 0 == i%3 {
			if content, err = sjson.Set(content, stringProperty, ""); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		} else if 1 == i%3 {
			if content, err = sjson.Set(content, stringProperty, stringThreshold); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		} else {
			if content, err = sjson.Set(content, stringProperty, "bbb"); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		}
		if _, err = client.AddDocument(schemaName, "", content); err != nil {
			t.Fatalf("add document fail: %s", err.Error())
		}
	}
	//check pagination
	var condition QueryCondition
	condition.
		MaxRecord(limit).
		SetOffset(beginOffset).
		DescendBy(floatProperty).
		PropertyGreaterOrEqual(intProperty, strconv.Itoa(intThreshold)).
		PropertyGreaterThan(floatProperty, fmt.Sprintf("%f", floatMinThreshold)).
		PropertyLessThan(floatProperty, fmt.Sprintf("%f", floatMaxThreshold)).
		PropertyEqual(boolProperty, strconv.FormatBool(boolThreshold)).
		PropertyEqual(stringProperty, stringThreshold)

	var docs []Document
	var recordLimit, offset, totalRecord = 0, 0, 0
	if docs, recordLimit, offset, totalRecord, err = client.QueryDocuments(schemaName, condition); err != nil {
		t.Fatalf("query documents fail: %s", err.Error())
	}
	var docCount = len(docs)
	t.Logf("%d / %d documents returned, offset %d, limit %d", docCount, totalRecord, offset, recordLimit)

	for index := 0; index < docCount; index++ {
		var doc = docs[index]
		var content = []byte(doc.Content)
		var intValue = json.Get(content, intProperty).ToInt()
		if intValue < intThreshold {
			t.Fatalf("unexpected int property %d at doc %d, must >= %d", intValue, index, intThreshold)
		}
		var floatValue = json.Get(content, floatProperty).ToFloat64()
		if floatValue < floatMinThreshold || floatValue > floatMaxThreshold {
			t.Fatalf("unexpected float property %f at doc %d, must between (%f, %f)",
				floatValue, index, floatMinThreshold, floatMaxThreshold)
		}
		var boolValue = json.Get(content, boolProperty).ToBool()
		if boolValue != boolThreshold {
			t.Fatalf("unexpected bool property %t at doc %d, must be %t", boolValue, index, boolThreshold)
		}
		var stringValue = json.Get(content, stringProperty).ToString()
		if stringValue != stringThreshold {
			t.Fatalf("unexpected string property %s at doc %d, must be %s", stringValue, index, stringThreshold)
		}
		t.Logf("%dth doc '%s' (offset %d), properties: int %d, float %f, string %s, bool %t",
			index, doc.ID, index+beginOffset, intValue, floatValue, stringValue, boolValue)
	}
	t.Log("query documents filtered by multi properties: ok")
}

func TestChainConnector_QueryIndexedDocumentsFilteredByMultiPropertiesWithOrder(t *testing.T) {
	const (
		stringProperty    = "s"
		intProperty       = "i"
		floatProperty     = "f"
		boolProperty      = "b"
		total             = 30
		limit             = 5
		beginOffset       = 1
		intThreshold      = 6
		floatMinThreshold = 9.9
		floatMaxThreshold = 90.0
		boolThreshold     = true
		stringThreshold   = "aaa"
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("query_docs_%d", r.Intn(9999))
	var schema = DocumentSchema{
		Name: schemaName,
		Properties: []DocumentProperty{
			{
				Name:    stringProperty,
				Type:    PropertyTypeString,
				Indexed: true,
			},
			{
				Name:    intProperty,
				Type:    PropertyTypeInteger,
				Indexed: true,
			},
			{
				Name:    floatProperty,
				Type:    PropertyTypeFloat,
				Indexed: true,
			},
			{
				Name:    boolProperty,
				Type:    PropertyTypeBoolean,
				Indexed: true,
			},
		},
	}
	if err = client.CreateSchema(schema.Name, schema.Properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	for i := 0; i < total; i++ {
		var content = "{}"
		if content, err = sjson.Set(content, intProperty, i); err != nil {
			t.Fatalf("set integer for doc fail: %s", err.Error())
		}
		if content, err = sjson.Set(content, floatProperty, float64(i)*2.22); err != nil {
			t.Fatalf("set float for doc fail: %s", err.Error())
		}
		if 0 == i%2 {
			if content, err = sjson.Set(content, boolProperty, true); err != nil {
				t.Fatalf("set boolean for doc fail: %s", err.Error())
			}
		} else {
			if content, err = sjson.Set(content, boolProperty, false); err != nil {
				t.Fatalf("set boolean for doc fail: %s", err.Error())
			}
		}
		if 0 == i%3 {
			if content, err = sjson.Set(content, stringProperty, ""); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		} else if 1 == i%3 {
			if content, err = sjson.Set(content, stringProperty, stringThreshold); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		} else {
			if content, err = sjson.Set(content, stringProperty, "bbb"); err != nil {
				t.Fatalf("set string for doc fail: %s", err.Error())
			}
		}
		if _, err = client.AddDocument(schemaName, "", content); err != nil {
			t.Fatalf("add document fail: %s", err.Error())
		}
	}
	//check pagination
	var condition QueryCondition
	condition.
		MaxRecord(limit).
		SetOffset(beginOffset).
		DescendBy(floatProperty).
		PropertyGreaterOrEqual(intProperty, strconv.Itoa(intThreshold)).
		PropertyGreaterThan(floatProperty, fmt.Sprintf("%f", floatMinThreshold)).
		PropertyLessThan(floatProperty, fmt.Sprintf("%f", floatMaxThreshold)).
		PropertyEqual(boolProperty, strconv.FormatBool(boolThreshold)).
		PropertyEqual(stringProperty, stringThreshold)

	var docs []Document
	var recordLimit, offset, totalRecord = 0, 0, 0
	if docs, recordLimit, offset, totalRecord, err = client.QueryDocuments(schemaName, condition); err != nil {
		t.Fatalf("query documents fail: %s", err.Error())
	}
	var docCount = len(docs)
	t.Logf("%d / %d documents returned, offset %d, limit %d", docCount, totalRecord, offset, recordLimit)

	for index := 0; index < docCount; index++ {
		var doc = docs[index]
		var content = []byte(doc.Content)
		var intValue = json.Get(content, intProperty).ToInt()
		if intValue < intThreshold {
			t.Fatalf("unexpected int property %d at doc %d, must >= %d", intValue, index, intThreshold)
		}
		var floatValue = json.Get(content, floatProperty).ToFloat64()
		if floatValue < floatMinThreshold || floatValue > floatMaxThreshold {
			t.Fatalf("unexpected float property %f at doc %d, must between (%f, %f)",
				floatValue, index, floatMinThreshold, floatMaxThreshold)
		}
		var boolValue = json.Get(content, boolProperty).ToBool()
		if boolValue != boolThreshold {
			t.Fatalf("unexpected bool property %t at doc %d, must be %t", boolValue, index, boolThreshold)
		}
		var stringValue = json.Get(content, stringProperty).ToString()
		if stringValue != stringThreshold {
			t.Fatalf("unexpected string property %s at doc %d, must be %s", stringValue, index, stringThreshold)
		}
		t.Logf("%dth doc '%s' (offset %d), properties: int %d, float %f, string %s, bool %t",
			index, doc.ID, index+beginOffset, intValue, floatValue, stringValue, boolValue)
	}
	t.Log("query indexed documents filtered by multi properties: ok")
}

func TestChainConnector_QueryDocumentsPagination(t *testing.T) {
	const (
		stringProperty = "s"
		intProperty    = "i"
		floatProperty  = "f"
		total          = 15
		limit          = 5
		beginOffset    = 2
	)

	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("query_docs_pagination_%d", r.Intn(9999))

	var schema = DocumentSchema{
		Name: schemaName,
		Properties: []DocumentProperty{
			{
				Name: stringProperty,
				Type: PropertyTypeString,
			},
			{
				Name: intProperty,
				Type: PropertyTypeInteger,
			},
			{
				Name: floatProperty,
				Type: PropertyTypeFloat,
			},
		},
	}
	var content = fmt.Sprintf("{\"%s\": \"aaa\", \"%s\": 123, \"%s\": 5.5}",
		stringProperty, intProperty, floatProperty)
	if err = client.CreateSchema(schema.Name, schema.Properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	for i := 0; i < total; i++ {
		if _, err = client.AddDocument(schemaName, "", content); err != nil {
			t.Fatalf("add document fail: %s", err.Error())
		}
	}
	//check pagination
	var docs []Document
	var count int
	for offset := beginOffset; offset < total; offset += limit {
		var expected = total - offset
		if expected > limit {
			expected = limit
		}
		var condition = new(QueryCondition).MaxRecord(limit).SetOffset(offset)

		if docs, _, _, count, err = client.QueryDocuments(schemaName, *condition); err != nil {
			t.Fatalf("query documents fail: %s", err.Error())
		}
		if expected != len(docs) {
			t.Fatalf("unexpected record count %d => %d from offset %d", len(docs), expected, offset)
		}
		if count != total {
			t.Fatalf("unexpected total count %d => %d", count, total)
		}
		t.Logf("%d documents returned from offset %d", len(docs), offset)
	}
	t.Log("query documents pagination: ok")
}

func TestChainConnector_QueryDocumentsPaginationSortByInteger(t *testing.T) {
	const (
		stringProperty = "s"
		intProperty    = "i"
		floatProperty  = "f"
		total          = 15
		limit          = 5
		beginOffset    = 2
	)

	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("query_docs_pagination_%d", r.Intn(9999))

	var schema = DocumentSchema{
		Name: schemaName,
		Properties: []DocumentProperty{
			{
				Name: stringProperty,
				Type: PropertyTypeString,
			},
			{
				Name: intProperty,
				Type: PropertyTypeInteger,
			},
			{
				Name: floatProperty,
				Type: PropertyTypeFloat,
			},
		},
	}
	var content = fmt.Sprintf("{\"%s\": \"aaa\", \"%s\": 123, \"%s\": 5.5}",
		stringProperty, intProperty, floatProperty)
	if err = client.CreateSchema(schema.Name, schema.Properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	for i := 0; i < total; i++ {
		if content, err = sjson.Set(content, intProperty, i); err != nil {
			t.Fatalf("set integer for doc fail: %s", err.Error())
		}
		if _, err = client.AddDocument(schemaName, "", content); err != nil {
			t.Fatalf("add document fail: %s", err.Error())
		}
	}
	//check pagination
	var docs []Document
	var count int
	for offset := beginOffset; offset < total; offset += limit {
		var expected = total - offset
		if expected > limit {
			expected = limit
		}
		var condition = new(QueryCondition).MaxRecord(limit).SetOffset(offset).AscendBy(intProperty)
		if docs, _, _, count, err = client.QueryDocuments(schemaName, *condition); err != nil {
			t.Fatalf("query documents fail: %s", err.Error())
		}
		if expected != len(docs) {
			t.Fatalf("unexpected record count %d => %d from offset %d", len(docs), expected, offset)
		}
		if count != total {
			t.Fatalf("unexpected total count %d => %d", count, total)
		}
		for j := 0; j < expected; j++ {
			var value = json.Get([]byte(docs[j].Content), intProperty).ToInt()
			if offset+j != value {
				t.Fatalf("unexpected int property %d => %d at %dth document from %d",
					value, offset+j, j, offset)
			}
		}
		t.Logf("%d documents returned from offset %d", len(docs), offset)
	}
	t.Log("query documents pagination sort by integer: ok")
}

func TestChainConnector_QueryContracts(t *testing.T) {
	const (
		recordStart = 0
		maxRecord   = 20
	)
	defer clearClientEnvironment()
	client, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	contracts, offset, _, total, err := client.QueryContracts(recordStart, maxRecord)
	if err != nil {
		t.Fatalf("query contracts fail: %s", err.Error())
	}
	t.Logf("%d / %d contracts returned from %d", len(contracts), total, offset)
	for _, contract := range contracts {
		t.Logf("contract-%s-v%d: modified %s, enabled: %t, trace: %t",
			contract.Name, contract.Version, contract.ModifiedTime, contract.Enabled, contract.Trace)
	}
}

func TestChainConnector_ConcurrentAddDocument(t *testing.T) {
	const (
		IntProperty    = "int_property"
		BoolProperty   = "bool_property"
		StringProperty = "string_property"
		FloatProperty  = "float_property"
		requestCount   = 200
		routineCount   = 50
	)

	type testDocument struct {
		IntProperty    int     `json:"int_property"`
		BoolProperty   bool    `json:"bool_property"`
		StringProperty string  `json:"string_property"`
		FloatProperty  float64 `json:"float_property"`
	}

	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("concurrent_add_doc_%d", r.Intn(9999))
	var properties = []DocumentProperty{
		{
			Name: IntProperty,
			Type: PropertyTypeInteger,
		},
		{
			Name: BoolProperty,
			Type: PropertyTypeBoolean,
		},
		{
			Name: StringProperty,
			Type: PropertyTypeString,
		},
		{
			Name: FloatProperty,
			Type: PropertyTypeFloat,
		},
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete schema fail: %s", err.Error())
		}
		t.Logf("schema '%s' deleted", schemaName)
	}()
	var doc = testDocument{
		IntProperty:    9,
		BoolProperty:   true,
		StringProperty: "sample",
		FloatProperty:  12.345,
	}
	var data string
	if data, err = json.MarshalToString(doc); err != nil {
		t.Fatalf("marshal content fail: %s", err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(routineCount)
	var begin = time.Now()
	var routineFail = make(chan error, 1)
	var routineDone = make(chan bool, 1)
	var run = func(id int) {
		var routineBegin = time.Now()
		for j := 0; j < requestCount; j++ {
			if _, err = client.AddDocument(schemaName, "", data); err != nil {
				t.Logf("routine %d: add document fail: %s", id, err.Error())
				routineFail <- err
				return
			}
		}
		var elapsed = time.Now().Sub(routineBegin) / time.Millisecond
		var avg = requestCount * 1000 / float64(elapsed)
		t.Logf("routine %d: %d document(s) added in %d millisecond(s), avg: %.2f",
			id, requestCount, elapsed, avg)
		wg.Done()
	}
	for i := 0; i < routineCount; i++ {
		go run(i)
	}
	go func() {
		wg.Wait()
		routineDone <- true
	}()
	select {
	case err = <-routineFail:
		t.Fatalf("routine fail: %s", err.Error())
	case <-routineDone:
		t.Log("all routine complete")
	}
	var elapsed = time.Now().Sub(begin) / time.Millisecond
	var total = requestCount * routineCount
	var tps = float64(total*1000) / float64(elapsed)
	t.Logf("%d document(s) added in %d millisecond(s) in total, tps: %.2f",
		total, elapsed, tps)
}

func TestChainConnector_ConcurrentUpdateDifferentDocument(t *testing.T) {
	const (
		IntProperty    = "int_property"
		BoolProperty   = "bool_property"
		StringProperty = "string_property"
		FloatProperty  = "float_property"
		requestCount   = 100
		routineCount   = 50
	)

	type testDocument struct {
		IntProperty    int     `json:"int_property"`
		BoolProperty   bool    `json:"bool_property"`
		StringProperty string  `json:"string_property"`
		FloatProperty  float64 `json:"float_property"`
	}

	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("concurrent_update_differ_doc_%d", r.Intn(9999))
	var properties = []DocumentProperty{
		{
			Name: IntProperty,
			Type: PropertyTypeInteger,
		},
		{
			Name: BoolProperty,
			Type: PropertyTypeBoolean,
		},
		{
			Name: StringProperty,
			Type: PropertyTypeString,
		},
		{
			Name: FloatProperty,
			Type: PropertyTypeFloat,
		},
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete schema fail: %s", err.Error())
		}
		t.Logf("schema '%s' deleted", schemaName)
	}()
	var doc = testDocument{
		IntProperty:    9,
		BoolProperty:   true,
		StringProperty: "sample",
		FloatProperty:  12.345,
	}
	var data string
	if data, err = json.MarshalToString(doc); err != nil {
		t.Fatalf("marshal content fail: %s", err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(routineCount)
	var begin = time.Now()
	var routineFail = make(chan error, 1)
	var routineDone = make(chan bool, 1)
	var run = func(id int) {
		var docID string
		if docID, err = client.AddDocument(schemaName, "", data); err != nil {
			t.Logf("routine %d: add document fail: %s", id, err.Error())
			routineFail <- err
			return
		}
		var routineBegin = time.Now()
		for j := 0; j < requestCount; j++ {
			if err = client.UpdateDocument(schemaName, docID, data); err != nil {
				t.Logf("routine %d: update document fail: %s", id, err.Error())
				routineFail <- err
				return
			}
		}
		var elapsed = time.Now().Sub(routineBegin) / time.Millisecond
		var avg = requestCount * 1000 / float64(elapsed)
		t.Logf("routine %d: %d document(s) updated in %d millisecond(s), avg: %.2f",
			id, requestCount, elapsed, avg)
		wg.Done()
	}
	for i := 0; i < routineCount; i++ {
		go run(i)
	}
	go func() {
		wg.Wait()
		routineDone <- true
	}()
	select {
	case err = <-routineFail:
		t.Fatalf("routine fail: %s", err.Error())
	case <-routineDone:
		t.Log("all routine complete")
	}
	var elapsed = time.Now().Sub(begin) / time.Millisecond
	var total = requestCount * routineCount
	var tps = float64(total*1000) / float64(elapsed)
	t.Logf("%d document(s) updated in %d millisecond(s) in total, tps: %.2f",
		total, elapsed, tps)
}

func TestChainConnector_ConcurrentUpdateSameDocument(t *testing.T) {
	const (
		IntProperty    = "int_property"
		BoolProperty   = "bool_property"
		StringProperty = "string_property"
		FloatProperty  = "float_property"
		requestCount   = 50
		routineCount   = 50
	)

	type testDocument struct {
		IntProperty    int     `json:"int_property"`
		BoolProperty   bool    `json:"bool_property"`
		StringProperty string  `json:"string_property"`
		FloatProperty  float64 `json:"float_property"`
	}

	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("concurrent_update_same_doc_%d", r.Intn(9999))
	var properties = []DocumentProperty{
		{
			Name: IntProperty,
			Type: PropertyTypeInteger,
		},
		{
			Name: BoolProperty,
			Type: PropertyTypeBoolean,
		},
		{
			Name: StringProperty,
			Type: PropertyTypeString,
		},
		{
			Name: FloatProperty,
			Type: PropertyTypeFloat,
		},
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		t.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			t.Fatalf("delete schema fail: %s", err.Error())
		}
		t.Logf("schema '%s' deleted", schemaName)
	}()
	var doc = testDocument{
		IntProperty:    9,
		BoolProperty:   true,
		StringProperty: "sample",
		FloatProperty:  12.345,
	}
	var data string
	if data, err = json.MarshalToString(doc); err != nil {
		t.Fatalf("marshal content fail: %s", err.Error())
	}
	var docID string
	if docID, err = client.AddDocument(schemaName, "", data); err != nil {
		t.Fatalf("add document fail: %s", err.Error())
		return
	}
	var wg sync.WaitGroup
	wg.Add(routineCount)
	var begin = time.Now()
	var routineFail = make(chan error, routineCount)
	var routineDone = make(chan bool, 1)
	var run = func(id int) {

		var routineBegin = time.Now()
		for j := 0; j < requestCount; j++ {
			if err = client.UpdateDocument(schemaName, docID, data); err != nil {
				t.Logf("routine %d: update document fail: %s", id, err.Error())
				routineFail <- err
				return
			}
		}
		var elapsed = time.Now().Sub(routineBegin) / time.Millisecond
		var avg = requestCount * 1000 / float64(elapsed)
		t.Logf("routine %d: %d document(s) updated in %d millisecond(s), avg: %.2f",
			id, requestCount, elapsed, avg)
		wg.Done()
	}
	for i := 0; i < routineCount; i++ {
		go run(i)
	}
	go func() {
		wg.Wait()
		routineDone <- true
	}()
	select {
	case err = <-routineFail:
		t.Fatalf("routine fail: %s", err.Error())
	case <-routineDone:
		t.Log("all routine complete")
	}
	var elapsed = time.Now().Sub(begin) / time.Millisecond
	var total = requestCount * routineCount
	var tps = float64(total*1000) / float64(elapsed)
	t.Logf("%d document(s) updated in %d millisecond(s) in total, tps: %.2f",
		total, elapsed, tps)
}

func TestChainConnector_ConcurrentCRUDCombination(t *testing.T) {
	const (
		//for 1 hour load test
		//requestCount = 1000
		//requestCount = 100
		requestCount = 50
		//for 10 min load test
		//requestCount = 200
		//routineCount = 200
		routineCount = 20
	)
	type statistic struct {
		ID           int
		Operates     int
		Processed    int
		TotalRequest int
	}

	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(routineCount)
	var begin = time.Now()
	var routineFail = make(chan error, routineCount)
	var routineDone = make(chan bool, 1)
	var collectChan = make(chan statistic, routineCount)
	var run = func(id int) {
		var routineBegin = time.Now()
		var totalOperates, operates = 0, 0
		for j := 0; j < requestCount; j++ {
			if operates, _, err = combineCRUD(id, client, r); err != nil {
				t.Logf("routine %d: execute CRUD fail: %s", id, err.Error())
				routineFail <- err
				return
			}
			totalOperates += operates
			collectChan <- statistic{
				ID:           id,
				Operates:     totalOperates,
				Processed:    j + 1,
				TotalRequest: requestCount,
			}
		}
		var elapsed = time.Now().Sub(routineBegin) / time.Millisecond
		var avg = float64(totalOperates*1000) / float64(elapsed)
		t.Logf("routine %d: %d operates executed in %d millisecond(s), avg: %.2f",
			id, totalOperates, elapsed, avg)
		wg.Done()
	}
	for i := 0; i < routineCount; i++ {
		go run(i)
	}
	go func() {
		wg.Wait()
		routineDone <- true
	}()

	var collectedStatus = map[int]statistic{}
	var collectTicker = time.NewTicker(time.Second * 3)
	var exit = false
	for !exit {
		select {
		case err = <-routineFail:
			t.Fatalf("routine fail: %s", err.Error())
		case status := <-collectChan:
			collectedStatus[status.ID] = status
		case <-collectTicker.C:
			for id, status := range collectedStatus {
				t.Logf("routine-%d: %d opreates executed, %d / %d batch processed",
					id, status.Operates, status.Processed, status.TotalRequest)
			}
		case <-routineDone:
			t.Log("all routine complete")
			exit = true
		}
	}

	var elapsed = time.Now().Sub(begin) / time.Millisecond
	var total = 0
	for _, status := range collectedStatus {
		total += status.Operates
	}
	var tps = float64(total*1000) / float64(elapsed)
	t.Logf("%d operates executed in %d millisecond(s) in total, tps: %.2f",
		total, elapsed, tps)
}

func TestChainConnector_ConcurrentContractOperations(t *testing.T) {
	const (
		//for 1 hour load test
		//requestCount = 1000
		requestCount = 100
		//requestCount = 500
		//routineCount = 200
		//routineCount = 100
		routineCount = 50
	)
	type statistic struct {
		ID           int
		Operates     int
		Processed    int
		TotalRequest int
	}

	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	var wg sync.WaitGroup
	wg.Add(routineCount)
	var begin = time.Now()
	var routineFail = make(chan error, routineCount)
	var routineDone = make(chan bool, 1)
	var collectChan = make(chan statistic, routineCount)
	var run = func(id int) {
		operates, usedTime, routineErr := contractOperates(id, client, r, requestCount, false)
		if routineErr != nil {
			t.Logf("routine %d: execute contract operates fail: %s", id, routineErr.Error())
			routineFail <- routineErr
			return
		}
		var elapsed = usedTime / time.Millisecond
		var avg = float64(operates*1000) / float64(elapsed)
		t.Logf("routine %d: %d operates executed in %d millisecond(s), avg: %.2f",
			id, operates, elapsed, avg)
		wg.Done()
	}
	for i := 0; i < routineCount; i++ {
		go run(i)
	}
	go func() {
		wg.Wait()
		routineDone <- true
	}()

	var collectedStatus = map[int]statistic{}
	var collectTicker = time.NewTicker(time.Second * 3)
	var exit = false
	for !exit {
		select {
		case err = <-routineFail:
			t.Fatalf("routine fail: %s", err.Error())
		case status := <-collectChan:
			collectedStatus[status.ID] = status
		case <-collectTicker.C:
			for id, status := range collectedStatus {
				t.Logf("routine-%d: %d opreates executed, %d / %d batch processed",
					id, status.Operates, status.Processed, status.TotalRequest)
			}
		case <-routineDone:
			t.Log("all routine complete")
			exit = true
		}
	}

	var elapsed = time.Now().Sub(begin) / time.Millisecond
	var total = 0
	for _, status := range collectedStatus {
		total += status.Operates
	}
	var tps = float64(total*1000) / float64(elapsed)
	t.Logf("%d operates executed in %d millisecond(s) in total, tps: %.2f",
		total, elapsed, tps)
}

func BenchmarkChainConnector_AddDocument(b *testing.B) {
	type testDocument struct {
		IntProperty    int     `json:"int_property"`
		BoolProperty   bool    `json:"bool_property"`
		StringProperty string  `json:"string_property"`
		FloatProperty  float64 `json:"float_property"`
	}

	const (
		IntProperty    = "int_property"
		BoolProperty   = "bool_property"
		StringProperty = "string_property"
		FloatProperty  = "float_property"
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		b.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("benchmark_add_doc_%d", r.Intn(9999))
	var properties = []DocumentProperty{
		{
			Name: IntProperty,
			Type: PropertyTypeInteger,
		},
		{
			Name: BoolProperty,
			Type: PropertyTypeBoolean,
		},
		{
			Name: StringProperty,
			Type: PropertyTypeString,
		},
		{
			Name: FloatProperty,
			Type: PropertyTypeFloat,
		},
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		b.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			b.Fatalf("delete schema fail: %s", err.Error())
		}
		b.Logf("schema '%s' deleted", schemaName)
	}()
	var doc = testDocument{
		IntProperty:    9,
		BoolProperty:   true,
		StringProperty: "sample",
		FloatProperty:  12.345,
	}
	var data string
	if data, err = json.MarshalToString(doc); err != nil {
		b.Fatalf("marshal content fail: %s", err.Error())
	}
	var beginTime = time.Now()
	for i := 0; i < b.N; i++ {
		if _, err = client.AddDocument(schemaName, "", data); err != nil {
			b.Fatalf("add document fail: %s", err.Error())
		}
	}
	var elapsed = time.Now().Sub(beginTime) / time.Millisecond
	var TPS = float64(b.N*1000) / float64(elapsed)
	b.Logf("benchmark add document: ok, %d document(s) added in %d millisecond(s), TPS: %.2f",
		b.N, elapsed, TPS)
}

func BenchmarkChainConnector_UpdateDocument(b *testing.B) {
	type testDocument struct {
		IntProperty    int     `json:"int_property"`
		BoolProperty   bool    `json:"bool_property"`
		StringProperty string  `json:"string_property"`
		FloatProperty  float64 `json:"float_property"`
	}

	const (
		IntProperty    = "int_property"
		BoolProperty   = "bool_property"
		StringProperty = "string_property"
		FloatProperty  = "float_property"
		docID          = "benchmark_update_doc_abc"
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		b.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("benchmark_update_doc_%d", r.Intn(9999))
	var properties = []DocumentProperty{
		{
			Name: IntProperty,
			Type: PropertyTypeInteger,
		},
		{
			Name: BoolProperty,
			Type: PropertyTypeBoolean,
		},
		{
			Name: StringProperty,
			Type: PropertyTypeString,
		},
		{
			Name: FloatProperty,
			Type: PropertyTypeFloat,
		},
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		b.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			b.Fatalf("delete schema fail: %s", err.Error())
		}
		b.Logf("schema '%s' deleted", schemaName)
	}()
	var doc = testDocument{
		IntProperty:    9,
		BoolProperty:   true,
		StringProperty: "sample",
		FloatProperty:  12.345,
	}
	var data string
	if data, err = json.MarshalToString(doc); err != nil {
		b.Fatalf("marshal content fail: %s", err.Error())
	}
	if _, err = client.AddDocument(schemaName, docID, data); err != nil {
		b.Fatalf("add document fail: %s", err.Error())
	}
	doc.IntProperty = 88
	doc.BoolProperty = false
	doc.StringProperty = "hello"
	doc.FloatProperty = 9.99

	if data, err = json.MarshalToString(doc); err != nil {
		b.Fatalf("marshal content fail: %s", err.Error())
	}

	var beginTime = time.Now()
	for i := 0; i < b.N; i++ {
		if err = client.UpdateDocument(schemaName, docID, data); err != nil {
			b.Fatalf("update document fail: %s", err.Error())
		}
	}
	var elapsed = time.Now().Sub(beginTime) / time.Millisecond
	var TPS = float64(b.N*1000) / float64(elapsed)
	var latest string
	if latest, err = client.GetDocument(schemaName, docID); err != nil {
		b.Fatalf("get latest content fail: %s", err.Error())
	}
	if latest != data {
		b.Fatalf("content mismatch %s => %s", latest, data)
	}
	b.Logf("benchmark update document: ok, %d document(s) updated in %d millisecond(s), TPS: %.2f",
		b.N, elapsed, TPS)
}

func BenchmarkChainConnector_RemoveDocument(b *testing.B) {
	type testDocument struct {
		IntProperty    int     `json:"int_property"`
		BoolProperty   bool    `json:"bool_property"`
		StringProperty string  `json:"string_property"`
		FloatProperty  float64 `json:"float_property"`
	}

	const (
		IntProperty    = "int_property"
		BoolProperty   = "bool_property"
		StringProperty = "string_property"
		FloatProperty  = "float_property"
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		b.Fatalf("prepare fail: %s", err.Error())
	}

	var schemaName = fmt.Sprintf("benchmark_remove_doc_%d", r.Intn(9999))
	var properties = []DocumentProperty{
		{
			Name: IntProperty,
			Type: PropertyTypeInteger,
		},
		{
			Name: BoolProperty,
			Type: PropertyTypeBoolean,
		},
		{
			Name: StringProperty,
			Type: PropertyTypeString,
		},
		{
			Name: FloatProperty,
			Type: PropertyTypeFloat,
		},
	}
	if err = client.CreateSchema(schemaName, properties); err != nil {
		b.Fatalf("create schema fail: %s", err.Error())
	}
	defer func() {
		if err = client.DeleteSchema(schemaName); err != nil {
			b.Fatalf("delete schema fail: %s", err.Error())
		}
		b.Logf("schema '%s' deleted", schemaName)
	}()
	var doc = testDocument{
		IntProperty:    9,
		BoolProperty:   true,
		StringProperty: "sample",
		FloatProperty:  12.345,
	}
	var data string
	if data, err = json.MarshalToString(doc); err != nil {
		b.Fatalf("marshal content fail: %s", err.Error())
	}

	var idList []string
	var docID string
	for i := 0; i < b.N; i++ {
		if docID, err = client.AddDocument(schemaName, "", data); err != nil {
			b.Fatalf("add document fail: %s", err.Error())
		}
		idList = append(idList, docID)
	}
	var beginTime = time.Now()
	for _, docID = range idList {
		if err = client.RemoveDocument(schemaName, docID); err != nil {
			b.Fatalf("remove document fail: %s", err.Error())
		}
	}
	var elapsed = time.Now().Sub(beginTime) / time.Millisecond
	var TPS = float64(b.N*1000) / float64(elapsed)
	b.Logf("benchmark remove document: ok, %d document(s) removed in %d millisecond(s), TPS: %.2f",
		b.N, elapsed, TPS)
}

func BenchmarkChainConnector_CRUD(b *testing.B) {
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		b.Fatalf("prepare fail: %s", err.Error())
	}

	b.ResetTimer()
	var totalOperates, operates = 0, 0
	var beginTime = time.Now()
	for i := 0; i < b.N; i++ {
		if operates, _, err = combineCRUD(i, client, r); err != nil {
			b.Fatalf("batch-%d fail: %s", i, err.Error())
		}
		totalOperates += operates
	}
	var elapsed = time.Now().Sub(beginTime) / time.Millisecond
	var TPS = float64(totalOperates*1000) / float64(elapsed)
	b.Logf("benchmark CURD: ok, %d operates in %d millisecond(s), TPS %.2f", totalOperates, elapsed, TPS)
}

func BenchmarkChainConnector_Contracts(b *testing.B) {
	const (
		loopCount = 10
	)
	defer clearClientEnvironment()
	client, r, err := prepareClientEnvironment()
	if err != nil {
		b.Fatalf("prepare fail: %s", err.Error())
	}

	b.ResetTimer()
	var totalOperates, operates = 0, 0
	var beginTime = time.Now()
	for i := 0; i < b.N; i++ {
		if operates, _, err = contractOperates(i, client, r, loopCount, true); err != nil {
			b.Fatalf("batch-%d fail: %s", i, err.Error())
		}
		totalOperates += operates
	}
	var elapsed = time.Now().Sub(beginTime) / time.Millisecond
	var TPS = float64(totalOperates*1000) / float64(elapsed)
	b.Logf("benchmark contract operates: ok, %d operates in %d millisecond(s), TPS %.2f", totalOperates, elapsed, TPS)
}

func TestChainConnector_Activate(t *testing.T) {
	defer clearClientEnvironment()
	client, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}

	if err = client.Activate(); err != nil {
		t.Fatalf("activate connection fail: %s", err.Error())
	}
	t.Log("activate test: ok")
}

func TestChainConnector_QueryBlocks(t *testing.T) {
	const (
		testCount = 100
		pageSize  = 20
	)
	defer clearClientEnvironment()
	client, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var currentHeight uint64
	_, currentHeight, _, _, _, err = client.GetStatus()
	if err != nil {
		t.Fatalf("get status fail: %s", err.Error())
	}
	var operates, walked int
	var elapsed time.Duration
	if operates, walked, elapsed, err = walkAllBlocks(client, currentHeight, testCount, pageSize); err != nil {
		t.Fatalf("run walk all blocks fail: %s", err.Error())
	}
	var ms = elapsed / time.Millisecond
	var TPS = float64(operates*1000) / float64(ms)
	t.Logf("walk all blocks test: ok, %d opreates in %d millisecond(s), TPS %.2f, %d blocks returned",
		operates, ms, TPS, walked)
}

func TestChainConnector_ConcurrentQueryBlocks(t *testing.T) {
	const (
		requestCount = 50
		routineCount = 10
		pageSize     = 20
	)
	type statistic struct {
		ID           int
		Operates     int
		Processed    int
		TotalRequest int
	}

	defer clearClientEnvironment()
	client, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var currentHeight uint64
	_, currentHeight, _, _, _, err = client.GetStatus()
	if err != nil {
		t.Fatalf("get status fail: %s", err.Error())
	}
	var wg sync.WaitGroup
	wg.Add(routineCount)
	var begin = time.Now()
	var routineFail = make(chan error, routineCount)
	var routineDone = make(chan bool, 1)
	var collectChan = make(chan statistic, routineCount)
	var run = func(id int) {
		var elapsed time.Duration
		var operates, walked = 0, 0
		if operates, walked, elapsed, err = walkAllBlocks(client, currentHeight, requestCount, pageSize); err != nil {
			t.Logf("routine %d: run walk all blocks fail: %s", id, err.Error())
		}
		collectChan <- statistic{
			ID:           id,
			Operates:     operates,
			Processed:    walked,
			TotalRequest: requestCount,
		}
		var avg = float64(operates*1000) / float64(elapsed/time.Millisecond)
		t.Logf("routine %d: %d operates executed in %d millisecond(s), avg: %.2f",
			id, operates, elapsed/time.Millisecond, avg)
		wg.Done()
	}
	for i := 0; i < routineCount; i++ {
		go run(i)
	}
	go func() {
		wg.Wait()
		routineDone <- true
	}()

	var collectedStatus = map[int]statistic{}
	var collectTicker = time.NewTicker(time.Second * 3)
	var exit = false
	for !exit {
		select {
		case err = <-routineFail:
			t.Fatalf("routine fail: %s", err.Error())
		case status := <-collectChan:
			collectedStatus[status.ID] = status
		case <-collectTicker.C:
			for id, status := range collectedStatus {
				t.Logf("routine-%d: %d opreates executed, %d / %d batch processed",
					id, status.Operates, status.Processed, status.TotalRequest)
			}
		case <-routineDone:
			t.Log("all routine complete")
			exit = true
		}
	}

	var elapsed = time.Now().Sub(begin) / time.Millisecond
	var total = 0
	for _, status := range collectedStatus {
		total += status.Operates
	}
	var tps = float64(total*1000) / float64(elapsed)
	t.Logf("%d operates executed in %d millisecond(s) in total, tps: %.2f",
		total, elapsed, tps)
}

func TestChainConnector_GetBlocks(t *testing.T) {
	const (
		testCount = 100
		pageSize  = 20
	)
	defer clearClientEnvironment()
	client, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var currentHeight uint64
	_, currentHeight, _, _, _, err = client.GetStatus()
	if err != nil {
		t.Fatalf("get status fail: %s", err.Error())
	}
	var operates int
	var elapsed time.Duration
	if operates, elapsed, err = walkBlockData(client, currentHeight, testCount, pageSize); err != nil {
		t.Fatalf("run walk block data fail: %s", err.Error())
	}
	var ms = elapsed / time.Millisecond
	var TPS = float64(operates*1000) / float64(ms)
	t.Logf("walk block data test: ok, %d blocks returned in %d millisecond(s), TPS %.2f",
		operates, ms, TPS)
}

func TestChainConnector_ConcurrentGetBlocks(t *testing.T) {
	const (
		requestCount = 50
		routineCount = 10
		pageSize     = 20
	)
	type statistic struct {
		ID           int
		Operates     int
		TotalRequest int
	}

	defer clearClientEnvironment()
	client, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var currentHeight uint64
	_, currentHeight, _, _, _, err = client.GetStatus()
	if err != nil {
		t.Fatalf("get status fail: %s", err.Error())
	}
	var wg sync.WaitGroup
	wg.Add(routineCount)
	var begin = time.Now()
	var routineFail = make(chan error, routineCount)
	var routineDone = make(chan bool, 1)
	var collectChan = make(chan statistic, routineCount)
	var run = func(id int) {
		var elapsed time.Duration
		var operates = 0
		if operates, elapsed, err = walkBlockData(client, currentHeight, requestCount, pageSize); err != nil {
			t.Logf("routine %d: run walk all blocks fail: %s", id, err.Error())
		}
		collectChan <- statistic{
			ID:           id,
			Operates:     operates,
			TotalRequest: requestCount,
		}
		var avg = float64(operates*1000) / float64(elapsed/time.Millisecond)
		t.Logf("routine %d: %d operates executed in %d millisecond(s), avg: %.2f",
			id, operates, elapsed/time.Millisecond, avg)
		wg.Done()
	}
	for i := 0; i < routineCount; i++ {
		go run(i)
	}
	go func() {
		wg.Wait()
		routineDone <- true
	}()

	var collectedStatus = map[int]statistic{}
	var collectTicker = time.NewTicker(time.Second * 3)
	var exit = false
	for !exit {
		select {
		case err = <-routineFail:
			t.Fatalf("routine fail: %s", err.Error())
		case status := <-collectChan:
			collectedStatus[status.ID] = status
		case <-collectTicker.C:
			for id, status := range collectedStatus {
				t.Logf("routine-%d: %d / %d opreates executed",
					id, status.Operates, status.TotalRequest)
			}
		case <-routineDone:
			t.Log("all routine complete")
			exit = true
		}
	}

	var elapsed = time.Now().Sub(begin) / time.Millisecond
	var total = 0
	for _, status := range collectedStatus {
		total += status.Operates
	}
	var tps = float64(total*1000) / float64(elapsed)
	t.Logf("%d operates executed in %d millisecond(s) in total, tps: %.2f",
		total, elapsed, tps)
}

func TestChainConnector_GetTransactions(t *testing.T) {
	const (
		testCount = 100
		pageSize  = 20
	)
	defer clearClientEnvironment()
	client, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var currentHeight uint64
	_, currentHeight, _, _, _, err = client.GetStatus()
	if err != nil {
		t.Fatalf("get status fail: %s", err.Error())
	}
	var operates, records int
	var elapsed time.Duration
	if operates, records, elapsed, err = walkTransactions(client, currentHeight, testCount, pageSize); err != nil {
		t.Fatalf("run walk transactions fail: %s", err.Error())
	}
	var ms = elapsed / time.Millisecond
	var TPS = float64(operates*1000) / float64(ms)
	t.Logf("walk transactions test: ok, %d transactions returned in %d millisecond(s), %d operates for TPS %.2f",
		records, ms, operates, TPS)
}

func TestChainConnector_ConcurrentGetTransactions(t *testing.T) {
	const (
		requestCount = 50
		routineCount = 20
		pageSize     = 20
	)
	type statistic struct {
		ID           int
		Operates     int
		Processed    int
		TotalRequest int
	}

	defer clearClientEnvironment()
	client, _, err := prepareClientEnvironment()
	if err != nil {
		t.Fatalf("prepare fail: %s", err.Error())
	}
	var currentHeight uint64
	_, currentHeight, _, _, _, err = client.GetStatus()
	if err != nil {
		t.Fatalf("get status fail: %s", err.Error())
	}
	var wg sync.WaitGroup
	wg.Add(routineCount)
	var begin = time.Now()
	var routineFail = make(chan error, routineCount)
	var routineDone = make(chan bool, 1)
	var collectChan = make(chan statistic, routineCount)
	var run = func(id int) {
		var routineBegin = time.Now()
		var operates, records = 0, 0
		if operates, records, _, err = walkTransactions(client, currentHeight, requestCount, pageSize); err != nil {
			t.Logf("routine %d: execute walk transactions fail: %s", id, err.Error())
			routineFail <- err
			return
		}
		collectChan <- statistic{
			ID:           id,
			Operates:     operates,
			Processed:    records,
			TotalRequest: requestCount,
		}
		var elapsed = time.Now().Sub(routineBegin) / time.Millisecond
		var avg = float64(operates*1000) / float64(elapsed)
		t.Logf("routine %d: %d operates executed in %d millisecond(s), avg: %.2f",
			id, operates, elapsed, avg)
		wg.Done()
	}
	for i := 0; i < routineCount; i++ {
		go run(i)
	}
	go func() {
		wg.Wait()
		routineDone <- true
	}()

	var collectedStatus = map[int]statistic{}
	var collectTicker = time.NewTicker(time.Second * 3)
	var exit = false
	for !exit {
		select {
		case err = <-routineFail:
			t.Fatalf("routine fail: %s", err.Error())
		case status := <-collectChan:
			collectedStatus[status.ID] = status
		case <-collectTicker.C:
			for id, status := range collectedStatus {
				t.Logf("routine-%d: %d opreates executed, %d / %d batch processed",
					id, status.Operates, status.Processed, status.TotalRequest)
			}
		case <-routineDone:
			t.Log("all routine complete")
			exit = true
		}
	}

	var elapsed = time.Now().Sub(begin) / time.Millisecond
	var total, records = 0, 0
	for _, status := range collectedStatus {
		total += status.Operates
		records += status.Processed
	}
	var tps = float64(total*1000) / float64(elapsed)
	t.Logf("%d operates executed in %d millisecond(s) in total, tps: %.2f, %d record returned",
		total, elapsed, tps, records)
}
