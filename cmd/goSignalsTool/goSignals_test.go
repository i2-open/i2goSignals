package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders/mongo_provider"
	ssef "i2goSignals/pkg/goSSEF/server"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"
var testLog = log.New(os.Stdout, "TOOL-TEST: ", log.Ldate|log.Ltime)

var testIssuer = "cluster.scim.example.com"
var testAudMulti = "cluster.example.com,monitor.example.com,partner.scim.example.com"
var testAudCluster = "cluster.example.com"
var testAudMonitor = "monitor.example.com"
var server1name = "test1server"
var server2name = "test2server"

type ssfInstance struct {
	server      *http.Server
	client      *http.Client
	provider    *mongo_provider.MongoProvider
	stream      model.StreamConfiguration
	app         ssef.SignalsApplication
	streamToken string
	startTime   *time.Time
}

type toolSuite struct {
	suite.Suite
	pd      *ParserData
	servers []*ssfInstance
	testDir string
}

func (suite *toolSuite) initialize() error {

	var err error
	dir, _ := os.MkdirTemp(os.TempDir(), "goSignals-*")
	suite.testDir = dir

	configName := fmt.Sprintf("%s/toolconfig.json", suite.testDir)
	err = os.Setenv("GOSIGNALS_HOME", configName)

	cli := &CLI{}
	cli.Globals.Config = configName

	fmt.Println("Test working directory: " + dir)
	suite.pd, err = initParser(cli)
	if err != nil {
		testLog.Printf(err.Error())
	}

	instance, err := createServer(server1name)
	if err != nil {
		testLog.Printf("Error starting %s: %s", server1name, err.Error())
		return err
	}
	suite.servers[0] = instance
	instance, err = createServer(server2name)
	if err != nil {
		testLog.Printf("Error starting %s: %s", server2name, err.Error())
		return err
	}
	suite.servers[1] = instance
	return nil
}

func (suite *toolSuite) cleanup() {

	for _, instance := range suite.servers {
		testLog.Printf("** Shutting down server %s...", instance.provider.Name())
		instance.app.Shutdown()
		time.Sleep(time.Second)
	}

	os.RemoveAll(suite.testDir)

}

func createServer(dbName string) (*ssfInstance, error) {
	var err error
	var instance ssfInstance
	mongo, err := mongo_provider.Open(TestDbUrl, dbName)
	if err != nil {
		testLog.Println("Mongo client error: " + err.Error())
		return nil, err
	}

	_ = mongo.ResetDb(true)

	listener, _ := net.Listen("tcp", "localhost:0")

	signalsApplication := ssef.StartServer(listener.Addr().String(), &*mongo, "")
	instance.app = *signalsApplication
	instance.server = signalsApplication.Server
	instance.client = &http.Client{}
	instance.provider = mongo
	nowTime := time.Now()
	instance.startTime = &nowTime

	go func() {
		_ = signalsApplication.Server.Serve(listener)
	}()
	return &instance, nil
}

func (suite *toolSuite) executeCommand(cmd string, confirm bool) ([]byte, error) {
	args := strings.Split(cmd, " ")
	var ctx *kong.Context
	ctx, err := suite.pd.parser.Parse(args)

	if err != nil {
		suite.pd.parser.Errorf("%s", err.Error())
		if err, ok := err.(*kong.ParseError); ok {
			log.Println(err.Error())
			_ = err.Context.PrintUsage(false)
			return nil, err
		}
	}

	output := os.Stdout
	input := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdout = w
	var ir, iw *os.File
	if confirm {
		ir, iw, _ = os.Pipe()
		os.Stdin = ir
		confirm := "Y\n"
		_, _ = iw.Write([]byte(confirm))
		_ = iw.Close()

	}

	err = ctx.Run(&suite.pd.cli.Globals)
	if confirm {
		os.Stdin = input
		ir.Close()
	}
	_ = w.Close()
	os.Stdout = output

	resultBytes, _ := io.ReadAll(r)
	_ = r.Close()

	return resultBytes, err
}

func TestTool(t *testing.T) {

	instances := make([]*ssfInstance, 2)
	s := toolSuite{
		servers: instances,
	}
	err := s.initialize()
	if err != nil {
		testLog.Println("Error initializing tests: " + err.Error())
	}

	defer s.cleanup()

	suite.Run(t, &s)

	testLog.Println("** TEST COMPLETE **")
}

func (suite *toolSuite) Test1_AddServers() {
	serverName := suite.servers[0].provider.Name()
	cmd := fmt.Sprintf("add server %s http://%s/", serverName, suite.servers[0].server.Addr)

	res, err := suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Add server successful")
	testLog.Printf("%s", res)
	server, err := suite.pd.cli.Data.GetServer(serverName)
	assert.NoError(suite.T(), err, "Add server successful")
	assert.Equal(suite.T(), serverName, server.Alias, "Found server and matched")

	serverName = suite.servers[1].provider.Name()
	cmd = fmt.Sprintf("add server %s http://%s/", serverName, suite.servers[1].server.Addr)
	res, err = suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Add server successful")
	testLog.Printf("%s", res)

	cmd = "show server " + serverName
	res, err = suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Show server successful")
	resultString := string(res)
	testLog.Printf("\n%s", resultString)
	assert.Contains(suite.T(), resultString, fmt.Sprintf("http://%s/jwks.json", suite.servers[1].server.Addr), "Has jwksuri")
}

func (suite *toolSuite) Test2_CreatePublisherKey() {
	var pemFile = fmt.Sprintf("%s/pem-%s.pem", suite.testDir, server1name)
	cmd := fmt.Sprintf("create key %s %s --file=%s", server1name, testIssuer, pemFile)

	_, err := suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Error creating issuer certificate")

	info, err := os.Stat(pemFile)
	assert.Greater(suite.T(), info.Size(), int64(10), "PEM file present (> 0 bytes)")

	cmd1 := fmt.Sprintf("get key %s --iss=%s", server1name, testIssuer)
	resBytes1, err := suite.executeCommand(cmd1, false)
	assert.NoError(suite.T(), err, "get key by server and iss parameter error")

	cmd2 := fmt.Sprintf("get key http://%s/jwks/%s", suite.servers[0].server.Addr, testIssuer)
	resBytes2, err := suite.executeCommand(cmd2, false)
	assert.NoError(suite.T(), err, "get key by url error")
	res1 := string(resBytes1)
	res2 := string(resBytes2)
	assert.Truef(suite.T(), res1 == res2, "Was same key returned")
}

func (suite *toolSuite) Test3_AddPushStream() {
	serverName := suite.servers[0].provider.Name()
	server1Addr := suite.servers[0].server.Addr
	cmd := fmt.Sprintf("create stream push receive %s --name=scim1Push --mode=FORWARD --aud=cluster.example.com,monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=*:prov:*:full,*:prov:delete --iss-jwks-url=http://%s/jwks/cluster.scim.example.com", serverName, server1Addr)

	res, err := suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")
	result := string(res)
	assert.Contains(suite.T(), result, "\"Issuer\": \"cluster.scim.example.com\"")
	endpoint := fmt.Sprintf("\"endpoint\": \"http://%s/events\"", server1Addr)
	assert.Contains(suite.T(), result, endpoint, "Event endpoint present")
	testLog.Println(fmt.Sprintf("Result:\n%s", res))

	streamConfig, err := suite.pd.cli.Data.GetStreamConfig("scim1Push")

	assert.Len(suite.T(), streamConfig.EventsDelivered, 4, "Should be 6 events delivered")

}

func (suite *toolSuite) Test4_UpdateStream() {
	// this test will modify scim1Push and change events to notice and full events
	cmd := fmt.Sprintf("set stream config scim1Push -e *:prov:*")

	updateBytes, err := suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Check for update error")
	result := string(updateBytes)
	assert.Contains(suite.T(), result, ":notice", "Check info events present")
	streamConfig, err := suite.pd.cli.Data.GetStreamConfig("scim1Push")
	assert.NoError(suite.T(), err, "Get updated stream had no error")
	assert.Equal(suite.T(), len(streamConfig.EventsDelivered), 9)
}

func (suite *toolSuite) Test8_GetStreamConfigTest() {
	serverName := suite.servers[0].provider.Name()

	serverSsf := suite.pd.cli.Data.Servers[serverName]

	streams := serverSsf.Streams
	assert.Len(suite.T(), streams, 2, "Should be 2 streams")

	for s := range streams {

		name := fmt.Sprintf("%s/stream-%s.json", suite.testDir, s)
		// assert.NoError(suite.T(), err, "Temp file create error")

		cmd := fmt.Sprintf("get stream config %s -o %s", s, name)
		fmt.Println("goSignals: " + cmd)
		resBytes, err := suite.executeCommand(cmd, true)
		if err != nil {
			return
		}
		cfgBytes, err := os.ReadFile(name)
		assert.NoError(suite.T(), err, "Opening result file")
		resString := string(resBytes)
		var config model.StreamConfiguration
		err = json.Unmarshal(cfgBytes, &config)
		assert.NoError(suite.T(), err, "Config was re-parsed")
		cfgString := string(cfgBytes)
		assert.Contains(suite.T(), resString, cfgString, "Confirm output")
		fmt.Printf("Result:\n%s", cfgString)

	}
	// cmd := fmt.Sprintf("create stream receive push %s", serverName)

}
