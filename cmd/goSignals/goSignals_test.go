package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/independentid/i2goSignals/internal/authUtil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/independentid/i2goSignals/internal/model"
	"github.com/independentid/i2goSignals/internal/providers/dbProviders/mongo_provider"
	ssef "github.com/independentid/i2goSignals/pkg/goSSEF/server"
)

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"
var testLog = log.New(os.Stdout, "TOOL-TEST: ", log.Ldate|log.Ltime)

var testIssuer = "cluster.scim.example.com"

// var testAudMulti = "cluster.example.com,monitor.example.com,partner.scim.example.com"
// var testAudCluster = "cluster.example.com"
// var testAudMonitor = "monitor.example.com"
var server1name = "test1server"
var server2name = "test2server"

type ssfInstance struct {
	server          *http.Server
	client          *http.Client
	provider        *mongo_provider.MongoProvider
	stream          model.StreamConfiguration
	app             ssef.SignalsApplication
	streamToken     string
	streamMgmtToken string
	iatToken        string
	projectId       string
	startTime       *time.Time
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

	_ = os.RemoveAll(suite.testDir)

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
	// args := strings.Split(cmd, " ")
	quoted := false
	args := strings.FieldsFunc(cmd, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})

	var ctx *kong.Context
	ctx, err := suite.pd.parser.Parse(args)

	if err != nil {
		suite.pd.parser.Errorf("%s", err.Error())
		var err *kong.ParseError
		if errors.As(err, &err) {
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
		_ = ir.Close()
	}
	_ = w.Close()
	os.Stdout = output

	resultBytes, _ := io.ReadAll(r)
	_ = r.Close()

	return resultBytes, err
}

func TestGoSignalsTool(t *testing.T) {

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

func (suite *toolSuite) Test0_MgmtTokens() {
	testLog.Println("Test 0 - Issue Stream Mgmt Tokens")
	var err error
	for _, instance := range suite.servers {
		testLog.Printf("  Getting registration IAT for %s...", instance.provider.Name())
		instance.iatToken, err = instance.provider.GetAuthIssuer().IssueProjectIat(nil)
		if err != nil {
			fmt.Printf("Error creating iat: %s", err.Error())
		}
		eat, err := instance.provider.GetAuthIssuer().ParseAuthToken(instance.iatToken)
		if err != nil {
			fmt.Printf("Error parsing iat: %s", err.Error())
		}
		project := eat.ProjectId
		assert.NotEqualf(suite.T(), "", project, "Check project not empty")

		testLog.Printf("  Getting Client admin token for %s...", instance.provider.Name())

		clientToken, err := instance.provider.GetAuthIssuer().IssueStreamClientToken(model.SsfClient{
			Id:            primitive.NewObjectID(),
			ProjectIds:    []string{eat.ProjectId},
			AllowedScopes: []string{authUtil.ScopeStreamAdmin, authUtil.ScopeStreamMgmt},
			Email:         "test@test.com",
			Description:   "server test",
		}, eat.ProjectId, true)
		instance.streamMgmtToken = clientToken

		testLog.Println("  Checking validation and project ids...")
		cat, err := instance.provider.GetAuthIssuer().ParseAuthToken(clientToken)
		assert.True(suite.T(), cat.IsAuthorized("", []string{authUtil.ScopeStreamAdmin}), "Check is authorized for mgmt")
		assert.Equal(suite.T(), project, cat.ProjectId, "Check project ids match")
		instance.projectId = eat.ProjectId
	}

}
func (suite *toolSuite) Test1_AddServers() {
	testLog.Println("Test 1 - Add Server Test")
	serverName := suite.servers[0].provider.Name()
	cmd := fmt.Sprintf("add server %s http://%s/ --desc=\"Add server test\" --email=test@example.com", serverName, suite.servers[0].server.Addr)

	res, err := suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Add server successful")
	testLog.Printf("%s", res)
	server, err := suite.pd.cli.Data.GetServer(serverName)
	assert.NoError(suite.T(), err, "Add server successful")
	assert.Equal(suite.T(), serverName, server.Alias, "Found server and matched")

	serverName = suite.servers[1].provider.Name()
	cmd = fmt.Sprintf("add server %s http://%s/ --desc=\"Add server test\" --email=test@example.com", serverName, suite.servers[1].server.Addr)
	res, err = suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Add server successful")
	testLog.Printf("%s", res)

	cmd = "show server " + serverName
	res, err = suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Show server successful")
	resultString := string(res)
	testLog.Printf("\n%s", resultString)
	assert.Contains(suite.T(), resultString, fmt.Sprintf("http://%s/jwks.json", suite.servers[1].server.Addr), "Has jwksuri")

	testLog.Println("  Test issuing IAT and Register Client with it")
	serverName = suite.servers[0].provider.Name()

	var iatFile = fmt.Sprintf("%s/iat-%s.txt", suite.testDir, server1name)
	cmd = fmt.Sprintf("create iat %s -o %s", serverName, iatFile)
	testLog.Println("Executing:\n" + cmd)
	res, err = suite.executeCommand(cmd, false)
	fmt.Println(string(res))
	info, err := os.Stat(iatFile)
	assert.Greater(suite.T(), info.Size(), int64(10), "IAT file present (> 10 bytes)")

	tokenBytes, err := os.ReadFile(iatFile)
	assert.NoError(suite.T(), err, "No error reading token file")

	testLog.Println("  Test adding server with IAT")
	// iat := res[5:]
	cmd = fmt.Sprintf("add server %s http://%s/ --desc=\"Add server test\" --email=test@example.com --iat=%s", serverName+"-a", suite.servers[0].server.Addr, tokenBytes)
	testLog.Println("Executing:\n" + cmd)
	res, err = suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "No error executing add server with iat")
	fmt.Println(string(res))
}

func (suite *toolSuite) Test2_CreatePublisherKey() {
	testLog.Println("Test 2 - Create Publisher Key")
	testLog.Println("  Create Key...")
	var pemFile = fmt.Sprintf("%s/pem-%s.pem", suite.testDir, server1name)
	cmd := fmt.Sprintf("create key %s %s --file=%s", server1name, testIssuer, pemFile)

	_, err := suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Error creating issuer certificate")

	info, err := os.Stat(pemFile)
	assert.Greater(suite.T(), info.Size(), int64(10), "PEM file present (> 10 bytes)")

	testLog.Println("  Get Key...")
	cmd1 := fmt.Sprintf("get key %s --iss=%s", server1name, testIssuer)
	resBytes1, err := suite.executeCommand(cmd1, false)
	assert.NoError(suite.T(), err, "get key by server and iss parameter error")

	testLog.Println("  Get Key by JwksUrl")
	cmd2 := fmt.Sprintf("get key http://%s/jwks/%s", suite.servers[0].server.Addr, testIssuer)
	resBytes2, err := suite.executeCommand(cmd2, false)
	assert.NoError(suite.T(), err, "get key by url error")
	res1 := string(resBytes1)
	res2 := string(resBytes2)
	assert.Truef(suite.T(), res1 == res2, "Was same key returned")
}

func (suite *toolSuite) Test3_PushStream() {
	testLog.Println("Test3 Test Push Stream Management.")
	testLog.Println("  Testing simple Add Push Receiver...")
	server2Name := suite.servers[1].provider.Name()
	server2Addr := suite.servers[1].server.Addr
	server1Addr := suite.servers[0].server.Addr
	cmd := fmt.Sprintf("create stream push receive %s --name=scim1Push --mode=FORWARD --aud=cluster.example.com,monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=*:prov:*:full,*:prov:delete --iss-jwks-url=http://%s/jwks/cluster.scim.example.com", server2Name, server1Addr)
	testLog.Println("Executing:\n" + cmd)
	res, err := suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")
	result := string(res)
	streamConfig, err := suite.pd.cli.Data.GetStreamConfig("scim1Push")
	assert.Contains(suite.T(), result, "\"iss\": \"cluster.scim.example.com\"")
	// endpoint := fmt.Sprintf("\"endpoint\": \"http://%s/events/%s", server2Addr, streamConfig.Id)
	// assert.Contains(suite.T(), result, endpoint, "Event endpoint present")
	testLog.Println(fmt.Sprintf("Result:\n%s", res))

	assert.Len(suite.T(), streamConfig.EventsDelivered, 4, "Should be 4 events delivered")

	testLog.Println("  Testing simple Create Stream Push Publisher...")
	cmd = fmt.Sprintf("create stream push publish %s --name=scim1PushPub --mode=F --aud=cluster.example.com,monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=*:prov:*:full,*:prov:delete --iss-jwks-url=http://%s/jwks/cluster.scim.example.com --event-url=%s --auth=\"%s\"", server1name, server1Addr, streamConfig.Delivery.PushReceiveMethod.EndpointUrl, streamConfig.Delivery.GetAuthorizationHeader())
	testLog.Println("Executing:\n" + cmd)
	res, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")
	streamConfigPub, err := suite.pd.cli.Data.GetStreamConfig("scim1PushPub")
	assert.Contains(suite.T(), result, "\"iss\": \"cluster.scim.example.com\"")
	// endpoint := fmt.Sprintf("\"endpoint\": \"http://%s/events/%s", server2Addr, streamConfig.Id)
	// assert.Contains(suite.T(), result, endpoint, "Event endpoint present")
	testLog.Println(fmt.Sprintf("Result:\n%s", res))

	assert.Len(suite.T(), streamConfigPub.EventsDelivered, 4, "Should be 4 events delivered")

	// Reset so the next subtest can work.
	res, err = suite.executeCommand("delete stream scim1PushPub", true)
	assert.Nil(suite.T(), err, "Check no error deleting scim1PushPub")
	streamCheck, _ := suite.pd.cli.Data.GetStreamAndServer("scim1PushPub")
	assert.Nil(suite.T(), streamCheck, "Stream should be deleted")

	testLog.Println("  Testing simple Create Stream Push Publisher using Connect...")
	cmd = fmt.Sprintf("create stream push publish %s --name=scim1PushPub -c scim1Push", server1name)
	testLog.Println("    Executing:\n" + cmd)
	res, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")
	streamConfigPub, err = suite.pd.cli.Data.GetStreamConfig("scim1PushPub")
	assert.Contains(suite.T(), result, "\"iss\": \"cluster.scim.example.com\"")
	// endpoint := fmt.Sprintf("\"endpoint\": \"http://%s/events/%s", server2Addr, streamConfig.Id)
	// assert.Contains(suite.T(), result, endpoint, "Event endpoint present")
	testLog.Println(fmt.Sprintf("Result:\n%s", res))

	assert.Len(suite.T(), streamConfigPub.EventsDelivered, 4, "Should be 4 events delivered")

	// Reset so the next subtest can work.
	res, err = suite.executeCommand("delete stream scim1PushPub", true)
	assert.Nil(suite.T(), err, "Check no error deleting scim1PushPub")
	streamCheck, _ = suite.pd.cli.Data.GetStreamAndServer("scim1PushPub")
	assert.Nil(suite.T(), streamCheck, "Stream should be deleted")

	testLog.Println("  Testing create stream publisher connection to existing scim1Push stream...")

	server1Name := suite.servers[0].provider.Name()
	cmd = fmt.Sprintf("create stream push connection %s scim1Push --mode=F", server1Name)
	testLog.Println("    Executing:\n" + cmd)

	res, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")
	res2 := string(res)
	assert.Contains(suite.T(), res2, "\"iss\": \"cluster.scim.example.com\"")

	pushConfig, err := suite.pd.cli.Data.GetStreamConfig("scim1Push-pub")
	assert.NoError(suite.T(), err, "Should be no error receiving push config")
	assert.NotNilf(suite.T(), pushConfig, "scim1Push-pub should exist")
	assert.NotNilf(suite.T(), pushConfig.Delivery.PushTransmitMethod, "Should be configured for push")
	endpoint2 := fmt.Sprintf("http://%s/events/%s", server2Addr, streamConfig.Id)
	assert.Equal(suite.T(), endpoint2, pushConfig.Delivery.PushTransmitMethod.EndpointUrl, "Push endpoint should match")

	testLog.Println(fmt.Sprintf("Result:\n%s", res2))

	testLog.Println("  Testing create stream connection at both ends..")
	cmd = fmt.Sprintf("create stream push connection %s %s --name=scimNotice --mode=FORWARD --aud=monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=*:prov:*:notice --iss-jwks-url=http://%s/jwks/cluster.scim.example.com", server1Name, server2Name, server1Addr)
	testLog.Println("    Executing:\n" + cmd)

	res, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")

	pushConfigRcv, err := suite.pd.cli.Data.GetStreamConfig("scimNotice-rcv")
	assert.Equal(suite.T(), "cluster.scim.example.com", pushConfigRcv.Iss, "Issuer is configured correctly")
	assert.NoError(suite.T(), err, "Should be no error receiving push config")
	assert.NotNilf(suite.T(), pushConfigRcv, "scimNotice-rcv should exist")
	assert.Equal(suite.T(), 3, len(pushConfigRcv.EventsDelivered), "Should be 3 events delivered")

	pushConfigPub, err := suite.pd.cli.Data.GetStreamConfig("scimNotice-pub")
	assert.NoError(suite.T(), err, "Should be no error getting poll config")
	assert.NotNilf(suite.T(), pushConfigPub, "scimNotice-pub should exist")
	assert.Equal(suite.T(), 3, len(pushConfigPub.EventsDelivered), "Should be 3 events delivered")
	endpoint3 := fmt.Sprintf("http://%s/events/%s", server2Addr, pushConfigRcv.Id)
	assert.Equal(suite.T(), endpoint3, pushConfigPub.Delivery.PushTransmitMethod.EndpointUrl, "Push endpoint should match")
}

func (suite *toolSuite) Test4_PollStream() {
	testLog.Println("Test 4 - Testing Poll Stream Management.")
	testLog.Println("  Testing Create Add Poll Publisher...")
	server2Name := suite.servers[1].provider.Name()
	server1Name := suite.servers[0].provider.Name()
	server1Addr := suite.servers[0].server.Addr
	cmd := fmt.Sprintf("create stream poll publish %s --name=scimPoll --aud=cluster.example.com,monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=*:event:(feed|sig):* --iss-jwks-url=http://%s/jwks/cluster.scim.example.com", server1Name, server1Addr)
	testLog.Println("    Executing:\n" + cmd)
	res, err := suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")
	result := string(res)
	assert.Contains(suite.T(), result, "\"iss\": \"cluster.scim.example.com\"")
	streamConfig, err := suite.pd.cli.Data.GetStreamConfig("scimPoll")
	assert.NoError(suite.T(), err, "Error getting stream config for scimPoll")
	assert.NotNilf(suite.T(), streamConfig, "Stream config for scimPoll not null")
	assert.Len(suite.T(), streamConfig.EventsDelivered, 4, "Should be 4 events delivered")
	endpoint := fmt.Sprintf("http://%s/poll/%s", server1Addr, streamConfig.Id)
	assert.Equal(suite.T(), endpoint, streamConfig.Delivery.PollTransmitMethod.EndpointUrl, "Event endpoint present")
	testLog.Println(fmt.Sprintf("Result:\n%s", res))

	testLog.Println("  Testing simple Create Stream Poll Receive...")
	cmd = fmt.Sprintf("create stream poll receive %s --name=scimPollRec --aud=cluster.example.com,monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=*:event:(feed|sig):* --iss-jwks-url=http://%s/jwks/cluster.scim.example.com --event-url=%s --auth=\"%s\"", server1Name, server1Addr, streamConfig.Delivery.PollTransmitMethod.EndpointUrl, streamConfig.Delivery.PollTransmitMethod.AuthorizationHeader)
	testLog.Println("    Executing:\n" + cmd)
	res, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")

	streamConfigPoll, err := suite.pd.cli.Data.GetStreamConfig("scimPollRec")
	assert.Len(suite.T(), streamConfigPoll.EventsDelivered, 4, "Should be 4 events delivered")

	// Reset so the next subtest can work.
	res, err = suite.executeCommand("delete stream scimPollRec", true)
	assert.Nil(suite.T(), err, "Check no error deleting scimPollRec")

	testLog.Println("  Testing Create Stream Receiver Poll using connect...")
	cmd = fmt.Sprintf("create stream poll receive %s --name=scimPollRec --connect=scimPoll", server1Name)
	testLog.Println("    Executing:\n" + cmd)
	res, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")

	streamConfigPoll, err = suite.pd.cli.Data.GetStreamConfig("scimPollRec")
	assert.Len(suite.T(), streamConfigPoll.EventsDelivered, 4, "Should be 4 events delivered")

	// Reset so the next subtest can work.
	res, err = suite.executeCommand("delete stream scimPollRec", true)
	assert.Nil(suite.T(), err, "Check no error deleting scimPollRec")

	testLog.Println("  Testing create stream receiver connection to existing scimPoll stream...")

	cmd = fmt.Sprintf("create stream poll connection scimPoll %s --mode=F", server2Name)
	testLog.Println("    Executing:\n" + cmd)

	res, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")
	res2 := string(res)
	assert.Contains(suite.T(), res2, "\"iss\": \"cluster.scim.example.com\"")

	pollConfig, err := suite.pd.cli.Data.GetStreamConfig("scimPoll-rcv")
	assert.NoError(suite.T(), err, "Should be no error receiving scimPoll-rcv config")
	assert.NotNilf(suite.T(), pollConfig, "scimPoll-rcv should exist")
	assert.Equal(suite.T(), model.ReceivePoll, pollConfig.Delivery.GetMethod(), "Should be configured for poll")

	testLog.Println(fmt.Sprintf("Result:\n%s", res2))

	testLog.Println("  Testing create polling stream connection at both ends..")
	cmd = fmt.Sprintf("create stream poll connection %s %s --name=scimMisc --mode=FORWARD --aud=monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=*:misc:* --iss-jwks-url=http://%s/jwks/cluster.scim.example.com", server1Name, server2Name, server1Addr)
	testLog.Println("    Executing:\n" + cmd)

	res, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream has no error")

	pollConfigRcv, err := suite.pd.cli.Data.GetStreamConfig("scimMisc-rcv")
	assert.Equal(suite.T(), "cluster.scim.example.com", pollConfigRcv.Iss, "Issuer is configured correctly")
	assert.NoError(suite.T(), err, "Should be no error receiving push config")
	assert.NotNilf(suite.T(), pollConfigRcv, "scimNotice-rcv should exist")
	assert.Equal(suite.T(), 1, len(pollConfigRcv.EventsDelivered), "Should be 1 events delivered")

	pollConfigPub, err := suite.pd.cli.Data.GetStreamConfig("scimMisc-pub")
	assert.NoError(suite.T(), err, "Should be no error getting push config")
	assert.NotNilf(suite.T(), pollConfigPub, "scimMisc-pub should exist")
	assert.Equal(suite.T(), 1, len(pollConfigPub.EventsDelivered), "Should be 1 events delivered")

}

func (suite *toolSuite) Test5_UpdateStream() {
	testLog.Println("Test 5 - Test Update Stream functionality:")
	// this test will modify scim1Push and change events to notice and full events

	cmd := fmt.Sprintf("set stream config scim1Push -e *:prov:*")

	resultBytes, err := suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Check for update error")
	result := string(resultBytes)
	assert.Contains(suite.T(), result, ":notice", "Check info events present")
	streamConfig, err := suite.pd.cli.Data.GetStreamConfig("scim1Push")
	assert.NoError(suite.T(), err, "Get updated stream had no error")
	assert.Equal(suite.T(), len(streamConfig.EventsDelivered), 9)
}

func (suite *toolSuite) Test6_Status() {
	testLog.Println("Test 6 - Stream Status.")
	testLog.Println("  Get Stream Status existing stream...")
	cmd := "get stream status scim1Push"
	testLog.Println(cmd)
	result, err := suite.executeCommand(cmd, true)
	testLog.Println(string(result))
	assert.Nil(suite.T(), err, "No error on Get stream status")

	testLog.Println("  Get stream status invalid...")
	cmd = "get stream status invalid"
	testLog.Println(cmd)
	result, err = suite.executeCommand(cmd, true)
	testLog.Println(string(result))
	assert.NotNilf(suite.T(), err, "There should be an error")
	assert.Contains(suite.T(), err.Error(), "Could not locate")

	testLog.Println("  Set Stream Status test")
	cmd = "set stream status scim1Push --state=disabled --reason=\"maintenance test\""
	testLog.Println(cmd)
	result, err = suite.executeCommand(cmd, true)
	resString := string(result)
	testLog.Println(resString)
	assert.Nil(suite.T(), err, "Check no error on set stream status")
	assert.Contains(suite.T(), resString, model.StreamStateDisable)

	cmd = "set stream status scim1Push --state=a --reason=restored"
	testLog.Println(cmd)
	result, err = suite.executeCommand(cmd, true)
	resString = string(result)
	testLog.Println(resString)
	assert.Nil(suite.T(), err, "Check no error on set stream status")
	assert.Contains(suite.T(), resString, model.StreamStateEnabled)

}

func (suite *toolSuite) Test7_Show() {
	testLog.Println("Test 7 - Show Commands.")

	testLog.Println("  Show Stream *...")
	cmd := "show stream *"

	testLog.Println("show stream *")
	result, err := suite.executeCommand(cmd, true)
	testLog.Println(string(result))
	assert.Nil(suite.T(), err, "No error on show stream *")

	testLog.Println("  Show stream scim1Push...")

	result, err = suite.executeCommand("show stream scim1Push", true)
	testLog.Println(string(result))
	assert.Nil(suite.T(), err, "No error on show stream *")

	testLog.Println("  Get stream config...")
	result, err = suite.executeCommand("get stream config", true)
	assert.Contains(suite.T(), err.Error(), "please provide the alias of a stream to get configuration", "Check value required error")
	testLog.Println(string(result))

	testLog.Println("  Help show stream...")
	result, err = suite.executeCommand("help show stream", true)
	testLog.Println(string(result))
	assert.Nil(suite.T(), err, "No error on help show stream")

	testLog.Println("  Show server missing param...")
	result, err = suite.executeCommand("show server", true)
	if err != nil {
		assert.Contains(suite.T(), err.Error(), "no currently selected server", "Check value required error")
	}
	testLog.Println(string(result))

	testLog.Println("  Show server <name> ...")
	cmd = fmt.Sprintf("show server %s", suite.servers[0].provider.Name())
	testLog.Println(cmd)
	result, err = suite.executeCommand(cmd, true)
	testLog.Println(string(result))
	assert.Nil(suite.T(), err, "No error on show server")

	testLog.Println("  Show server xyz (fail test)...")
	cmd = "show server xyz"
	testLog.Println(cmd)
	result, err = suite.executeCommand(cmd, true)
	testLog.Println(string(result))
	assert.Contains(suite.T(), err.Error(), "server xyz not defined", "Check value required error")

	testLog.Println("  Show server * ...")
	cmd = "show server *"
	testLog.Println(cmd)
	result, err = suite.executeCommand(cmd, true)
	testLog.Println(string(result))
	assert.Nil(suite.T(), err, "No error on show server *")

	testLog.Println(" Show auth scim1Push ...")
	result, err = suite.executeCommand("show auth scim1Push", true)
	testLog.Println(string(result))
	assert.Nil(suite.T(), err, "No error on show authorization")
}

func (suite *toolSuite) Test8_GetStreamConfigTest() {
	serverName := suite.servers[0].provider.Name()

	serverSsf := suite.pd.cli.Data.Servers[serverName]

	streams := serverSsf.Streams
	assert.Len(suite.T(), streams, 4, "Should be 6 streams")

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
		testLog.Printf("Result:\n%s", cfgString)

	}
	// cmd := fmt.Sprintf("create stream receive push %s", serverName)

}

func (suite *toolSuite) Test9_GenAndPoll() {
	testLog.Println("Test 9 - Generate route and Poll")

	testLog.Println("  Resetting streams...")
	server1Name := suite.servers[0].provider.Name()
	server2Name := suite.servers[1].provider.Name()
	// server2Addr := suite.servers[1].server.Addr
	server1Addr := suite.servers[0].server.Addr

	// reset existing configuration
	for alias := range suite.pd.cli.Data.Servers["test2server"].Streams {
		_, err := suite.executeCommand("delete stream "+alias, true)
		assert.Nil(suite.T(), err, "Check no error deleting "+alias)
	}
	for alias := range suite.pd.cli.Data.Servers["test1server"].Streams {
		_, err := suite.executeCommand("delete stream "+alias, true)
		assert.Nil(suite.T(), err, "Check no error deleting "+alias)
	}

	testLog.Println("  Waiting for deletions to settle out...")
	time.Sleep(time.Second * 2)

	testLog.Println()
	testLog.Println()

	testLog.Println("  Create a new for generator key...")
	iss := "gen.scim.example.com"
	var pemFile = fmt.Sprintf("%s/pem-%s.pem", suite.testDir, iss)
	cmd := fmt.Sprintf("create key %s %s --file=%s", server1name, iss, pemFile)
	_, err := suite.executeCommand(cmd, false)
	assert.NoError(suite.T(), err, "Error creating issuer certificate")

	testLog.Println("  Create PUSH connection between server 1 and 2...")
	cmd = fmt.Sprintf("create stream push connection %s %s --name=scimHop --mode=FORWARD --aud=receiver.example.com --iss=%s --events=*:prov:create:* --iss-jwks-url=http://%s/jwks/%s", server1Name, server2Name, iss, server1Addr, iss)
	testLog.Println("    Executing:\n" + cmd)

	_, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream connection has no error")

	testLog.Println("  Creating receiver stream for generator...")
	cmd = fmt.Sprintf("create stream push receive %s --name=generator --mode=FORWARD --aud=receiver.example.com --iss=%s --events=*:prov:create:* --iss-jwks-url=http://%s/jwks/gen.scim.example.com", server1Name, iss, server1Addr)
	testLog.Println("    Executing:\n" + cmd)

	_, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream generator has no error")

	testLog.Println("  Creating polling endpoint on " + server2Name + "...")
	cmd = fmt.Sprintf("create stream poll publish %s --name=poller --mode=F --aud=receiver.example.com --iss=%s --events=*:prov:create:* --iss-jwks-url=http://%s/jwks/gen.scim.example.com", server2Name, iss, server1Addr)
	testLog.Println("    Executing:\n" + cmd)
	_, err = suite.executeCommand(cmd, true)
	assert.NoError(suite.T(), err, "Add stream poller has no error")

	testLog.Println("  Generating event and sending...")
	cmd = "generate generator --event=create:full"
	testLog.Println("    Executing:\n" + cmd)
	res, err := suite.executeCommand(cmd, true)
	testLog.Printf("Results:\n%s", string(res))
	assert.NoError(suite.T(), err, "Gen event has no error")

	testLog.Println("  Testing poller to get event...")
	cmd = "poll poller -t 15 --return-immediately=true --loop=false"
	testLog.Println("    Executing:\n" + cmd)
	res, err = suite.executeCommand(cmd, true)
	testLog.Printf("Results:\n%s", string(res))
	assert.NoError(suite.T(), err, "Poll for event has no error")
}
