# i2goSignals Server Configuration Properties

Currently i2goSignals has minimal configuration properties. The current values are:

| Area / Parameter   | Description                                                                                | Default                                                |
|--------------------|--------------------------------------------------------------------------------------------|--------------------------------------------------------|
| **Server**         |                                                                                            |                                                        |
| `PORT`             | The port number on which goSignals will serve requests.                                    | 8888                                                   |
| `BASE_URL`         | The host and port of the server. e.g. 127.0.0.1:8888                                       | 127.0.0.1:<PORT> or 127.0.0.1:8888                     |
| <BR>**TLS Config** | <BR>To be implemented!                                                                     |                                                        |
| <BR>**Mongo DB**   |                                                                                            |                                                        |
| `MONGO_URL`        | The connection URL used to connect to a Mongo DB. Note: Should be a clustered replica set. | mongodb://root:dockTest@0.0.0.0:8880<br>_testing only_ |
| `DBNAME`           | The name of the database to store goSignals data                                           | ssef                                                   |
| <BR>**Roles**      |                                                                                            |                                                        |
| `SSEF_ADMIN_ROLE`  | The role to use to identify clients with administrative rights within a project            | ADMIN                                                  |



For the goSignals tool the following properties are defined:

| Area / Parameter | Description                                                | Default                  |
|------------------|------------------------------------------------------------|--------------------------|
| `GOSIGNALS_HOME` | File path to store local administration configuration data | ~/.goSignals/config.json |

