# SDK of Chain Connector in Go

用于访问和操作链平台的Go语言SDK，要求go 18以上版本。

The Go language SDK for accessing and operating on blockchain platform. Go version 18 or above is required.

## 项目 Project

### 编译 Compile

```bash
$go build
```


### 运行测试用例 Run testing

运行测试前，先将平台分配的私钥数据保存在"access_key.json"中，然后配置"test.json"的参数host和port设定好到网关的连接信息。

Before running the test, save the private key data allocated by the platform in "access_key.json", and then configure the parameters host and port of "test.json" to the service address of the gateway.

```bash
$go test
```



## 使用范例 Usage

### 连接链平台 Connect the chain

首先使用平台分配的私钥数据构建Connector，然后连接链平台的gateway模块。

Initial the connector using the private key data allocated by the chain platform, then connect to the gateway module.

```go
var access PrivateAccessPayload
//load access from file
//....
    
//create connector
var conn *ChainConnector    
if conn, err = NewConnectorFromAccess(access.PrivateData); err != nil {
    err = fmt.Errorf("create connector fail: %s", err.Error())
    return
}

//connect to gateway
_, err = conn.Connect(gatewayHost, gatewayPort)
```



## 构建与管理数字资产 Build and manage digital assets

首先为数字资产定义数据范式（Schema），然后就能够基于该Schema添加、修改、删除和查询数字资产(Document)。所有变更痕迹自动使用区块链技术持久化存储，并且能够通过getSchemaLog和getDocumentLog接口查询。

Define a data schema for digital assets, and then you can add, update, delete, and query documents (digital assets) under the schema. All changes are automatically persistently stored using blockchain and could be queried using getSchemaLog and getDocumentLog.

```go
//create new schema
var schemaName = "sample"
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
var schema DocumentSchema
schema, err = conn.GetSchema(schemaName)

//add a document
var content = "{\"name\": \"hello\", \"age\": 20, \"available\": true}"
var docID string
docID, err = conn.AddDocument(schemaName, "", content);

//check a document
var exists bool
exists, err = conn.HasDocument(schemaName, docID)
if (exists){
	//update a existed document
    var updatedContent = "{\"name\": \"alice\", \"age\": 18, \"available\": false}"
    err = conn.UpdateDocument(schemaName, docID, updatedContent)
}

//get change trace of a document
var version uint64
var logs []TraceLog
version, logs, err = conn.GetDocumentLog(schemaName, docID)

//query documents
var condition = new(QueryCondition)
    .AscendBy("name")
    .MaxRecord(20)
    .SetOffset(0)

var docs []Document
var limit, offset, total int
docs, limit, offset, total, err = conn.QueryDocuments(schemaName, *condition)

//remove document
err = conn.RemoveDocument(schemaName, docID)

```



### 部署和调用智能合约 Deploy and invoke the Smart Contract

部署智能合约时，需要设定合约名称和执行步骤。调用时，指定合约名称和调用参数就可以启动执行。系统允许打开追踪开关，查看合约执行计划和实际运行情况。

It is necessary to assign a name and execute steps to deploy a Smart Contract. Then initiate execution using the contract name and call parameters. The system can enable the trace option for a contract, which allows the user to review the contract's execution plan and steps.



```go
const contractName = "contract_create"
var contractDefine = ContractDefine{
    steps: [
        {
            action: "create_doc",
            params: ["$s", "@1", "@2"],
        },
        {
            action: "set_property",
            params: ["$s", "catalog", "@3"],
        },
        {
            action: "set_property",
            params: ["$s", "balance", "@4"],
        },
        {
            action: "set_property",
            params: ["$s", "number", "@5"],
        },
        {
            action: "set_property",
            params: ["$s", "available", "@6"],
        },
        {
            action: "set_property",
            params: ["$s", "weight", "@7"],
        },
        {
            action: "update_doc",
            params: ["@1", "$s"],
        },
        {
            action: "submit",
        },
    ],
}

//check existed contract
var exists bool
exists, err = conn.HasContract(contractName)
if (exists)) {
    //withdraw existed contract
    err = conn.WithdrawContract(contractName)
    log.printf("previous contract %s removed\n", contractName)
}

//deploy contact
err = conn.DeployContract(contractName, contractDefine)

//enable trace option
var info ContractInfo
info, err = conn.GetContractInfo(createContractName)
if !info.Trace {
    err = conn.EnableContractTrace(contractName)
}

var docID = "contract-doc"
var parameters = []string {
    schemaName,
    docID,
    schemaName,
    fmt.Sprintf("%f", r.Float64()),
    fmt.Sprintf("%d", r.Int()),
    fmt.Sprintf("%t", 1 == r.Intn(10)%2),
    fmt.Sprintf("%f", r.Float64())
}

//call contract with parameters
err = conn.CallContract(contractName, parameters)

```



### 检查区块链与交易 Audit the block chain and transaction

通过SDK能够获取并检查链、区块、交易的全部详细信息，用于审计数据安全性和检查后台运行情况。

Through the SDK, you can obtain and check all the details of chains, blocks, and transactions, which can be used to audit data security and monitor the background operation.

```go
//check chain status
var world, height uint64
var previousBlock, genesisBlock, allocatedID string
world, heigh, previousBlock, genesisBlock, allocatedID, err  = conn.GetStatus()

//query blocks from height 1 to 10
var idList []string
var currentHeight uint64
idList, currentHeight, err = conn.QueryBlocks(1, 10)
for _, blockID := range idList {
    //get block data
    var blockData BlockData
    blockData, err = conn.GetBlock(blockID)
    //query transactions in a block
    var transList []string
	var offset, limit, total int
    transList, offset, limit, total, err = conn.QueryTransactions(blockID, 0, 20)
    for _, transID := range transList {
        //get transaction data
        var transactionData TransactionData
        transactionData, err = conn.GetTransaction(blockID, transID)
    }
}

```

