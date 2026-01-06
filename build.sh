echo "\nGo Signals builder utility\n"
echo "\nThis utility is meant for building docker images only.\nUse the Make utility for normal development.\n"

tag="v0.8"
test="N"
doPush="N"
aIn="amd64,arm64"
optString="amhtdcpn:"
multi="N"
while getopts ${optString} OPTION; do
  case "$OPTION" in
    a)
      aIn=${OPTARG}
      echo "  .. selecting arch: $aIn"
      ;;
    t)
      test="Y"
      ;;
    n)
      tag=${OPTARG}
      echo "  ..using docker version tag: $tag"
      ;;
    p)
      echo "  ..push to Docker Hub requested"
      doPush="Y"
      ;;
    c)
      echo "* Installing goSignals CLI"
      if ! command -v goSignals &> /dev/null
      then
          go install github.com/i2-open/i2goSignals/cmd/goSignals@latest
          exit 1
      fi
      hexa help
      exit
      ;;

    m)
      echo "  ..multi platform build selected"
      multi="Y"
      ;;
    *)
      echo "Usage: ./build.sh -b -t <tag> -p"
      echo "  -a         Architectures (comma separated) [386|amd64|arm64|mips64|mips64le|ppc64|riscv64|s390x (default amd64]"
      echo "             Default is \"amd64,arm64\" when -m selected"
      echo "  -t         Performs build and test (default: build only)"
      echo "  -m         Build for multi-platform"
      echo "  -n <value> The version value (e.g. 1.1.1)"
      echo "  -p         Push the image to docker [default: not pushed]"
      echo "  -c         Check and install the Hexa CLI from github.com/hexa-org/policy-mapper"
      exit 1
  esac
done

echo "" # Newline

if [ "$test" = 'Y' ];then
    echo "* Building and running tests ..."
    go build ./...
    go test ./...
    echo ""
fi

echo "* building docker container image ($tag)..."
echo "  - downloading latest chainguard platform image"
docker pull docker.io/chainguard/static:latest

if [ "$multi" = 'Y' ];then
   IFS=', ' read -ra archs <<< "$aIn"

   echo "Performing platform builds..."

   for arch in "${archs[@]}"
   do
     echo "----------------------------------------------------"
     echo "  - performing build for $arch"

     CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o ./goSignals ./cmd/goSignals/...
     CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o ./goSignalsServer ./cmd/goSignalsServer/...

     docker buildx build --push --platform "linux/$arch" --provenance=true --sbom=true --tag "independentid/i2gosignals:$tag-$arch" .
     echo ""
   done
else
  echo "  - building for local platform"
  CGO_ENABLED=0 GOOS=linux go build -o ./goSignals ./cmd/goSignals/...
  CGO_ENABLED=0 GOOS=linux go build -o ./goSignalsServer ./cmd/goSignalsServer/...
  docker build --tag "i2gosignals:$tag" .
fi


echo "  Build complete. Execute using docker compose"