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
var dir = os.TempDir()

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
	cli     *CLI
	parser  *kong.Kong
	servers []*ssfInstance
}

func (suite *toolSuite) initialize() error {
	suite.cli = &CLI{}
	suite.cli.Data = ConfigData{
		Servers: map[string]SsfServer{},
	}
	var err error
	suite.parser, err = kong.New(suite.cli,
		kong.Name("goSignals"),
		kong.Description("i2goSignals client administration tool"),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact:      true,
			Summary:      true,
			Tree:         true,
			NoAppSummary: false,
		}),
		kong.UsageOnError(),
		kong.Writers(os.Stdout, os.Stdout),

		kong.NoDefaultHelp(),
		kong.Bind(&suite.cli.Globals),
		kong.Exit(func(int) {}),
	)
	f, err := os.CreateTemp("", "ConfigTest*.json")
	if err != nil {
		testLog.Println(err.Error())
		return err
	}
	suite.cli.Globals.Config = f.Name()
	_ = suite.cli.Data.Load(&suite.cli.Globals)

	instance, err := createServer("test1server")
	if err != nil {
		testLog.Printf("Error starting %s: %s", "test1server", err.Error())
		return err
	}
	suite.servers[0] = instance
	instance, err = createServer("test2server")
	if err != nil {
		testLog.Printf("Error starting %s: %s", "test2server", err.Error())
		return err
	}
	suite.servers[1] = instance
	return nil
}

func (suite *toolSuite) cleanup() {

	_ = os.Remove(suite.cli.Config)

	for _, instance := range suite.servers {
		testLog.Printf("** Shutting down server %s...", instance.provider.Name())
		instance.app.Shutdown()
		time.Sleep(time.Second)
	}

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
	ctx, err := suite.parser.Parse(args)

	if err != nil {

		suite.parser.Errorf("%s", err.Error())
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
	if confirm {
		ir, iw, _ := os.Pipe()
		os.Stdin = ir
		confirm := "Y\n"
		_, _ = iw.Write([]byte(confirm))
		_ = iw.Close()
	}

	err = ctx.Run(&suite.cli.Globals)

	os.Stdin = input
	_ = w.Close()
	os.Stdout = output

	resultBytes, _ := io.ReadAll(r)

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

	suite.Run(t, &s)

	s.cleanup()

	testLog.Println("** TEST COMPLETE **")
}

func (suite *toolSuite) Test1_AddServers() {
	serverName := suite.servers[0].provider.Name()
	cmd := fmt.Sprintf("add server %s http://%s/", serverName, suite.servers[0].server.Addr)

	res, err := suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Add server successful")
	testLog.Printf("%s", res)
	server, err := suite.cli.Data.GetServer(serverName)
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

func (suite *toolSuite) Test2_AddPushStream() {
	serverName := suite.servers[0].provider.Name()

	cmd := fmt.Sprintf("create stream receive push %s", serverName)

	res, err := suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")
	result := string(res)
	assert.Contains(suite.T(), result, "\"iss\": \"DEFAULT\"")
	endpoint := fmt.Sprintf("\"endpoint\": \"http://%s/events\"", suite.servers[0].server.Addr)
	assert.Contains(suite.T(), result, endpoint, "Event endpoint present")
	testLog.Println(fmt.Sprintf("Result:\n%s", res))

	var inbound = true
	reg := model.RegisterParameters{
		Audience:      []string{"TEST2ndStream"},
		Issuer:        "DEFAULT",
		Inbound:       &inbound,
		RouteMode:     model.RouteModeImport,
		Method:        model.DeliveryPush,
		IssuerJWKSUrl: suite.cli.Create.Stream.IssJwksUrl,
		EventUris:     []string{"*:prov:*:full", "*:prov:delete"},
	}

	server, _ := suite.cli.Data.GetServer(serverName)

	_ = suite.cli.executeCreateRequest("test2", reg, server, "Test PUSH Receiver")

	assert.NoError(suite.T(), err, "Add stream has no error")
	result = string(res)
	assert.Contains(suite.T(), result, "\"iss\": \"DEFAULT\"")
	endpoint = fmt.Sprintf("\"endpoint\": \"http://%s/events\"", suite.servers[0].server.Addr)
	assert.Contains(suite.T(), result, endpoint, "Event endpoint present")
	testLog.Println(fmt.Sprintf("Result:\n%s", res))

	streamConfig, err := suite.cli.Data.GetStreamConfig("test2")

	assert.Len(suite.T(), streamConfig.EventsDelivered, 4, "Should be 6 events delivered")

}

func (suite *toolSuite) Test3_GetTest() {
	serverName := suite.servers[0].provider.Name()

	serverSsf := suite.cli.Data.Servers[serverName]

	streams := serverSsf.Streams
	assert.Len(suite.T(), streams, 2, "Should be 2 streams")
	// dir, err := os.MkdirTemp("", "TestCfg*")

	for s := range streams {

		name := fmt.Sprintf("%scfg-%s.json", dir, s)
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
